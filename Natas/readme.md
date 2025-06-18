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
