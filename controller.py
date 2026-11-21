"""
    py controller.py status
    py controller.py on
    py controller.py off
    py controller.py temp +1 or -1 or +2 + how much u want lol
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

PROJECT = Path(__file__).resolve().parent 
TOKEN_FILE = PROJECT / ".tcl_token.json"

AWS_REGION = "ap-southeast-1"
MIN_TEMP, MAX_TEMP = 16, 30

def load_env():
    """Copy KEY=VALUE lines from .env into os.environ."""
    env_file = PROJECT / ".env"
    if not env_file.exists():
        sys.exit("error: no .env file - copy .env.example to .env and fill it in")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())

def setting(name, default=None):
    value = os.environ.get(name, default)
    if not value:
        sys.exit(f"error: {name} is missing from .env")
    return value

def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def send(method, url, headers, body=None):
    """Make an HTTP request and return the JSON response."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            text = response.read()
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode(errors="replace")
        raise RuntimeError(f"{url.split('?')[0]} returned HTTP {e.code}: {detail}")
    return json.loads(text) if text else {}


# start login code

def login():
    username = setting("TCL_USERNAME")
    if username.isdigit():  # 0812345678 -> +66812345678
        username = "+" + setting("TCL_PHONE_PREFIX", "66") + username.lstrip("0")

    body = {
        "username": username,
        "password": md5(setting("TCL_PASSWORD")),
        "channel": "app",
        "captchaRule": 2,
        "equipment": 2,
        "osType": 1,
        "osVersion": "6.0",
        "clientVersion": "4.8.1",
        "deviceModel": "AndroidAndroid SDK built for x86",
    }
    headers = {
        "content-type": "application/json; charset=UTF-8",
        "user-agent": "Android",
        "th_platform": "android",
        "th_version": "4.8.1",
        "th_appbulid": "830", #app misspelling
    }
    data = send("POST", "https://pa.account.tcl.com/account/login?clientId=54148614",
                headers, json.dumps(body).encode())
    if data.get("status") != 1:
        raise RuntimeError(f"login failed: {data.get('msg')}")

    TOKEN_FILE.write_text(json.dumps({"token": data["token"]}))
    return data["token"]


def saved_token():
    """Return the saved login token if it has more than an hour left, else None."""
    try:
        token = json.loads(TOKEN_FILE.read_text())["token"]
        payload = token.split(".")[1]
        expires = json.loads(base64.urlsafe_b64decode(payload + "==="))["exp"]
    except (OSError, ValueError, KeyError, IndexError):
        return None
    return token if expires - time.time() > 3600 else None

# aws access
def get_aws_identity(token):
    """Ask TCL which AWS identity and IoT server this account uses."""
    timestamp = str(int(time.time() * 1000))
    nonce = str(uuid.uuid4()).upper()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "TCLHome/6.1.3 (iPhone; iOS 26.4.2; Scale/3.00)",
        "Platform": "ios",
        "Appversion": "7.4.0",
        "Thomeversion": "6.1.3",
        "Accept-Language": "th",
        "Appid": "f6hek6hdpt64jrw596",
        "Ssotoken": token,
        "Timestamp": timestamp,
        "Nonce": nonce,
        "Sign": md5(timestamp + nonce),
        "Countrycode": setting("TCL_COUNTRY", "TH"),
        "Accesstoken": "",
        "Timezone": setting("TCL_TIMEZONE", "Asia/Bangkok"),
    }
    data = send("GET", "https://sgp-iot-api-prod.tcljd.com/v1/auth/service/loadBalance", headers)
    if data.get("code") != 200:
        raise RuntimeError(f"loadBalance failed: {data.get('message')}")
    return data["data"]


def get_aws_keys(identity):
    """Trade the AWS identity for temporary AWS keys."""
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
    }
    body = {
        "IdentityId": identity["cognitoId"],
        "Logins": {"cognito-identity.amazonaws.com": identity["cognitoToken"]},
    }
    data = send("POST", f"https://cognito-identity.{AWS_REGION}.amazonaws.com/",
                headers, json.dumps(body).encode())
    return data["Credentials"]


@lru_cache  # connect once per run, even if we read and then change the AC
def connect():
    """Steps 1-3. Returns (iot_host, aws_keys)."""
    token = saved_token()
    try:
        identity = get_aws_identity(token or login())
    except RuntimeError:
        if token is None:
            raise
        identity = get_aws_identity(login())  # saved token was rejected - log in again

    # mqttEndpoint looks like "wss://abc-ats.iot.ap-southeast-1.amazonaws.com:443/mqtt"
    host = identity["mqttEndpoint"].split("://")[-1].split(":")[0].split("/")[0]
    return host, get_aws_keys(identity)


# AWS iot

def aws_signed_headers(method, host, path, query, body, keys):
    """AWS Signature Version 4 - proves to AWS that we hold the keys."""
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    today = now[:8]
    scope = f"{today}/{AWS_REGION}/iotdata/aws4_request"
    signed_headers = "host;x-amz-date;x-amz-security-token"

    canonical_request = "\n".join([
        method,
        quote(path, safe="/~"),  # AWS wants the already-encoded path encoded again
        query,
        f"host:{host}\nx-amz-date:{now}\nx-amz-security-token:{keys['SessionToken']}\n",
        signed_headers,
        hashlib.sha256(body).hexdigest(),
    ])
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        now,
        scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    signing_key = ("AWS4" + keys["SecretKey"]).encode()
    for part in (today, AWS_REGION, "iotdata", "aws4_request"):
        signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    return {
        "X-Amz-Date": now,
        "X-Amz-Security-Token": keys["SessionToken"],
        "Authorization": f"AWS4-HMAC-SHA256 Credential={keys['AccessKeyId']}/{scope}, "
                         f"SignedHeaders={signed_headers}, Signature={signature}",
    }


def aws_request(method, path, query="", body=b""):
    host, keys = connect()
    headers = aws_signed_headers(method, host, path, query, body, keys)
    url = f"https://{host}{path}" + (f"?{query}" if query else "")
    return send(method, url, headers, body or None)


def read_ac():
    """Return the AC's current state, e.g. {"powerSwitch": 1, "targetTemperature": 23, ...}."""
    device = quote(setting("TCL_DEVICE_ID"), safe="")
    shadow = aws_request("GET", f"/things/{device}/shadow")
    state = shadow.get("state", {})
    return {**state.get("reported", {}), **state.get("desired", {})}


def change_ac(**settings):
    """Send new settings to the AC, e.g. change_ac(powerSwitch=1)."""
    topic = f"$aws/things/{setting('TCL_DEVICE_ID')}/shadow/update"
    message = {"state": {"desired": settings}, "clientToken": f"mobile_{int(time.time() * 1000)}"}
    aws_request("POST", f"/topics/{quote(topic, safe='')}", "qos=1", json.dumps(message).encode())


# commands start here

def status():
    ac = read_ac()
    if ac.get("powerSwitch") == 1:
        print("Power:  on")
    else:
        print("Power:  off")

    print(f"Set to: {ac.get('targetTemperature')}C")
    print(f"Room:   {ac.get('currentTemperature')}C")



def power(on):
    if on:
        change_ac(powerSwitch=1)
        print("Turned on.")
    else:
        change_ac(powerSwitch=0)
        print("Turned off.")


def change_temp(step):
    current = read_ac().get("targetTemperature") or 24
    new = max(MIN_TEMP, min(MAX_TEMP, current + step))
    change_ac(targetTemperature=new)
    print(f"Temperature: {current}C --> {new}C")


def main():
    load_env()
    args = sys.argv[1:]

    try:
        if args == ["status"]:
            status()
        elif args == ["on"]:
            power(True)
        elif args == ["off"]:
            power(False)
        elif len(args) == 2 and args[0] == "temp" and args[1][:1] in "+-" and args[1][1:].isdigit():
            change_temp(int(args[1]))
        else:
            print(__doc__)
            sys.exit(1)
    except (RuntimeError, OSError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
