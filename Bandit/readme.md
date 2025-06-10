### Bandit Level 0 → Level 1
**Key Takeaways**: Learn how to log into a server using SSH from a command-line terminal.
The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

**File**: readme

**Command**:

        cat readme

### Bandit Level 1 → Level 2
**Key Takeaways**: Learn how to read files with special characters, which is "-" in this case.
The password for the next level is stored in a file called - located in the home directory.

**File**: -

**Command**:

        cat ./-

### Bandit Level 2 → Level 3
**Key Takeaways**: Learn how to read files with spaces in its file name.
The password for the next level is stored in a file called spaces in this filename located in the home directory.

**File**: spaces in this filename

**Command**: 

        cat "spaces in this filename"
        
### Bandit Level 3 → Level 4
**Key Takeaways**: Learn how to see all files in a directory, by using the -a (--all) argument to the ls command.
The password for the next level is stored in a hidden file in the inhere directory.

**File**: .hidden

**Command**:

        cd inhere
        ls -a
        cat .hidden

### Bandit Level 4 → Level 5
**Key Takeaways**: Learn how to discover the type of a file, by using the file command.
The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.

**Command**: 

        file ./-file*

**Explanation**:

*file*: a Linux utility that examines the content of a file, not just the extension, to determine its type (e.g., ASCII text, binary, image, etc.)

*./file**: uses a glob pattern to match all files in the current directory starting with file (e.g., file01, file_ab, fileXYZ)

**Note**: human-readable file means a file with only ASCII text in this context.

**File**: -file07

### Bandit Level 5 → Level 6
**Key Takeaways**: Learn how to find a targeted file given a set of properties, by using the find command.
The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties: human-readable, 1033 bytes in size, not executable.

**Command**: 

        cd inhere
        find -type f -readable ! -executable -size 1033c

**Explanation**:

*-type f* – restricts the search to regular files (not directories, symlinks, etc.).

*-size 1033c* – looks for files that are exactly 1033 bytes in size.

*c* means bytes (you could also use k for kilobytes, M for megabytes, etc.)

*! -executable* – filters out executable files, meaning it will only return files that are not executable. This helps ensure you're dealing with plain text or human-readable files.

**File**: maybehere07/.file2

### Bandit Level 6 → Level 7
**Key Takeaways**: Learn how to find a targeted file given ownership, group, and size criteria by using the find command, and how to suppress permission errors during search. The password for the next level is stored in a file somewhere on the system with the following properties: owned by user bandit7, owned by group bandit6, and exactly 33 bytes in size.

**Command**:

        find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null

**Explanation**:

*-type f* – restricts the search to regular files (not directories, symlinks, etc.).

*-user bandit7* – files owned by the user bandit7.

*-group bandit6* – files owned by the group bandit6.

*-size 33c* – files exactly 33 bytes in size.

*2>/dev/null* – suppresses permission denied errors.

**File**: /var/lib/dpkg/info/bandit7.password

### Bandit Level 7 → Level 8
**Key Takeaways**: Learn how to search for a specific word within a file, by using the grep command. The password for the next level is stored in the file data.txt next to the word millionth.

**Command**:

        grep millionth data.txt

**File**: data.txt

### Bandit Level 8 → Level 9
**Key Takeaways**: Learn how to search within a file given a set of criteria, by using the sort and uniq commands, in addition to piping within the terminal. The password for the next level is stored in the file data.txt and is the only line of text that occurs only once.

**Command**:

        cat data.txt | sort | uniq -u

**Explanation**:

*sort* – Sorts the lines alphabetically (required before using uniq, because uniq only detects duplicates in adjacent lines).

*uniq -u* – Filters the sorted output to only show lines that appear exactly once (unique lines).

**File**: data.txt

### Bandit Level 9 → Level 10
**Key Takeaways**: Learn how to search for strings within a file that does not contain only ASCII characters, by using the strings and grep command. The password for the next level is stored in the file data.txt in one of the few human-readable strings, beginning with several ‘=’ characters.

**Command**:

        strings data.txt | grep ===

**Explanation**:

*strings* – Extracts printable (human-readable) ASCII text from a file — typically used on binary files.

*grep ===* – Searches for lines containing the string ===.

**File**: data.txt

### Bandit Level 10 → Level 11
**Key Takeaways**: Learn how to decode base64 encoded data, using the base64 command. The password for the next level is stored in the file data.txt, which contains base64 encoded data.

**Command**:

        base64 -d data.txt

**Explanation**:

*base64 -d* – Decodes data that has been encoded using the Base64 encoding scheme.

**File**: data.txt

### Bandit Level 11 → Level 12
**Key Takeaways**: Learn how to transform strings, using the tr command. The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions (Rot13 substitution cipher).

**Command**:

        cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'

**Explanation**:

*tr 'A-Za-z' 'N-ZA-Mn-za-m'* – Performs ROT13 decoding or encoding by shifting each letter 13 places in the alphabet.

- 'tr' → Translates characters from one set to another, character by character.
- 'A-Za-z' → Matches all uppercase and lowercase letters.
- 'N-ZA-Mn-za-m' → Rearranges the alphabet to shift letters by 13 places.

**File**: data.txt

### Bandit Level 12 → Level 13
**Key Takeaways**: Learn how to convert hexdump files and extract compressed files, using the xxd and various (de)compression utility commands respectively. The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv (read the manpages!).

**Steps**:

*Step 1:* First, make a new directory of your choice under /tmp. Next, copy data.txt to this new directory.

        cp data.txt /tmp/arnav

*Step 2:* The file command identifies data.txt as an ASCII text file, but when you view its contents, it’s actually a hex dump. Convert the hex dump into binary.

        xxd -r data.txt > file

*Step 3:* "*file file*" shows us that the converted hex dump contains gzip compressed data. Rename *file* as *file.gz* using "*mv file file.gz*." Unzip the file using the command:

        gzip -d file.gz

*Step 4:* "*file file*" shows that the file was compressed with bzip2. Rename it to *file.bz2* using "*mv file file.bz2*". Then unzip it using the command:

        bzip2 -d file.bz2

*Step 5:* "*file file*" shows that the file was compressed with gzip. Rename it to *file.gz* using "*mv file file.gz*". Then unzip it using *gzip -d file.gz*.

*Step 6:* "*file file*" shows that the file was compressed with POSIX tar. Rename it to *file.tar* using "*mv file file.tar*". Then extract it using the command:

        tar xf file.tar 

to get data5.bin.

*Step 7:* Remove unnecessary files like data.txt and file.tar using "*rm*". "*file data5.bin*" shows that the file was compressed with POSIX tar. Rename it to *data5.tar* using "*mv data5.bin data5.tar*". Then extract it using "*tar xf data5.tar*" to get data6.bin.

*Step 8:* "*file data6.bin*" shows that the file was compressed with bzip2. Rename it to *data6.bz2* using "*mv data6.bin data6.bz2*". Then extract the file using "*bzip2 -d data6.bz2*" to get data6.

*Step 9:* "*file data6*" shows that the file was compressed with POSIX tar. Rename it to *data6.tar* using "*mv data6 data6.tar*". Then extract the file using the command "*tar xf data6.tar*" to get data8.bin.

*Step 10:* "*file data8.bin*" shows that the file was compressed with gzip. Rename it to *data8.gz* using "*mv data8.bin data8.gz*". Then extract the file using the command "*gzip -d data8.gz*" to get data8.

*Step 11:* "*file data8*" shows that the file contains only ASCII text. Read the file using "*cat data8*" to get the password.

### Bandit Level 13 → Level 14
**Key Takeaways**: Learn how to log in to a server using a SSH (RSA) private key, using the ssh command. The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on.

**Approach**:

*Step 1: Attempted Direct SSH Login from bandit13*

Tried accessing the bandit14 account directly from the bandit13 session using the ssh -i option with the private key provided.
        
        bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost

Access was denied due to permission issues.

*Step 2: Transferred the Private Key to Local Machine*

Copied the contents of the private key into a local file and attempted to SSH into the Bandit server as bandit14 from the local machine using the *ssh* command. 

        ssh -p 2220 bandit14@bandit.labs.overthewire.org -i private.key
        
Again, permission was denied due to the private key file being accessible by others and being unprotected.

*Step 3: Inspected and Corrected Key File Permissions*

Verified the permissions of the private key file (using ls -l) and found they were too open, which is not accepted by SSH for authentication. Resolved this by running chmod 700 <keyfile> to restrict access appropriately (read, write, and execute for the owner only).
        
        chmod 700 private.key

*Step 4: Successful Login:*

Reattempted the SSH connection using the corrected key permissions. This time, authentication was successful and access to the bandit14 account was granted.

**Step 5: Got the password*

Used *cat* command on the path provided to obtain the password.

### Bandit Level 14 → Level 15
**Key Takeaways**: Learn how to send data to another host, using the telnet command. The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

**Approach**:

*Step 1:* Login to the bandit server as bandit14 using the password obtained in the previous level.

*Step 2:* Connect to port 30000 on localhost using telnet/nc.

        telnet localhost 30000

*Step 3:* Enter the level 14 password and enter. If the password checks out, the password for the next level will be received.

### Bandit Level 15 → Level 16
**Key Takeaways**: Learn how to send data to another host using SSL encryption, using the openssl and s_client commands. The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption. Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…

**Approach**:

*Step 1:* Login to the bandit server as bandit15 using the password obtained in the previous level.

*Step 2:* Connect to port 30001 on localhost using *ncat --ssl* or *openssl*.

        ncat --ssl localhost 30001
                or
        openssl s_client -connect localhost:30001

*Step 3:* Enter the level 15 password and enter. If the password checks out, the password for the next level will be received.

### Bandit Level 16 → Level 17
**Key Takeaways**: Learn how to identify listening ports within a server, using the nmap, openssl and s_client command. The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

**Approach**:

*Step 1:* Run an nmap scan on the range of ports 31000-32000.

        nmap -p 31000-32000 localhost

*Step 2:* Run an nmap scan on the resultant open ports with the -A parameter.

Note: *-A* parameter to nmap enables OS and version detection, script scanning, and traceroute (Basically, additional info about the ports).

        nmap -p 31046,31518,31691,31790,31960 -A localhost

*Step 3:* Only one port can be seen having an ssl speaking server running an unknown service - port 31790. Connect to the port using *openssl* command with *-ign_eof* (Not using it might result into a KEYUPDATE).

        openssl s_client -connect localhost:31790 -ign_eof

An RSA private key will be received.

*Step 4:* Copy this key into a file on the local machine. Grant all file permissions to the owner using the *chmod 700* command. 

*Step 5:* Use this keyfile to connect to the bandit server with bandit17 user using *ssh* command.

### Bandit Level 17 → Level 18
**Key Takeaways**: Learn how to compare the contents of 2 files, using the diff command. There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new. 
NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19.

**Approach**:

*Step 1:* Compare the contents of the files using *diff* command.

        diff passwords.old passwords.new
        
**Note:** The output of the *diff* command is dependent on the order of the parameters supplied to the command. If passwords.new is the second parameter, the second string that is printed in the output is the password for the next level.

### Bandit Level 18 → Level 19
**Key Takeaways**: Learn how to log in to a server via SSH without running .bash files (e.g. .bashrc and .bash_logout), using the ssh command with a set of parameters. The password for the next level is stored in a file readme in the home directory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

**Approach**:

*Step 1:* Use the 'command' feature of *ssh* to execute a command on the remote machine.

        ssh -p 2220 bandit18@bandit.labs.overthewire.org cat readme
        
**Note:** If a command is specified, it will be executed on the remote host instead of a login shell.

### Bandit Level 19 → Level 20
**Key Takeaways**: Learn how to take on the role of another user, using a setuid binary. To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

**Approach**:

*Step 1:* Execute the bandit20-do setuid file with a *cat* command as bandit20 (owner).

        ./bandit20-do cat /etc/bandit_pass/bandit20
        
**Note:** Executing *file bandit20-do* shows us that the file is a setuid ELF 32-bit LSB executable. Running the command allows us to take on the role of user bandit20 temporarily, because of the setuid (set user ID) executable.

### Bandit Level 20 → Level 21
**Key Takeaways**: Learn how to open a listening port and communicate using it, using the nc command. There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).
NOTE: Try connecting to your own network daemon to see if it works as you think.

**Approach**:

To complete this level, you’ll need two terminals, both logged in as bandit20.

*Step 1 (Terminal A):*

Start a listener using netcat on an arbitrary port (e.g., 9999):

        nc -l -p 9999

This will act as a server, waiting for incoming connections.

*Step 2 (Terminal B):*

Run the suconnect setuid binary with the same port number:

        ./suconnect 9999

This connects to the netcat listener you started on Terminal A.

*Step 3 (Terminal A):*

When prompted, input the password for bandit20. If the password is correct, the suconnect program will validate it and send back the password for bandit21 over the same connection — which will appear in Terminal A.

### Bandit Level 21 → Level 22
**Key Takeaways**: Learn how to read shell scripts that form part of a cron job. A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

**Approach**:

*Step 1:* Start by navigating to the /etc/cron.d directory. Here, you’ll find three cron job files corresponding to the next three levels. These are plain ASCII text files.
Open cronjob_bandit22, as it pertains to the level we're working on.

        cd /etc/cron.d
        ls
        cat cronjob_bandit22.sh

Inside, you'll see that it runs a script located at /usr/bin/cronjob_bandit22.sh.

*Step 2:* Upon examining the script, you’ll notice that the password for the next level is being written in a file called t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv in the /tmp directory.

        cat /usr/bin/cronjob_bandit22.sh.
        cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

### Bandit Level 22 → Level 23
**Key Takeaways**: Learn how to modify shell scripts that form part of a cron job. A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed. NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

**Approach**:

*Step 1:* Start by navigating to the /etc/cron.d directory. Here, you’ll find three cron job files corresponding to the next three levels. These are plain ASCII text files.
Open cronjob_bandit23, as it pertains to the level we're working on.

        cd /etc/cron.d
        ls
        cat cronjob_bandit23.sh

Inside, you'll see that it runs a script located at /usr/bin/cronjob_bandit23.sh. Open the file.

        cat /usr/bin/cronjob_bandit23.sh.

*Step 2:* Examining the script, it appears that the value assigned to the mytarget variable leads us to the password, since it points to a directory at /tmp/$mytarget. Since the script is executed by a cron job running as the bandit23 user, the myname variable will be set to bandit23.

By manually evaluating the expression assigned to mytarget with myname=bandit23, we can determine the exact directory path.

        echo I am user bandit23 | md5sum | cut -d ' ' -f 1

We get the value of mytarget as "8ca319486bfbbc3663ea0fbe81326349".

*Step 3:* Once we enter the correct value of mytarget, we can navigate to /tmp/$mytarget and retrieve the password for the next level.

        cat /tmp/8ca319486bfbbc3663ea0fbe81326349

### Bandit Level 23 → Level 24
**Key Takeaways**: Learn how to insert a shell script into an existing cron job. A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed. NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level! NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around...

**Approach**:

*Step 1:* Start by navigating to the /etc/cron.d directory. Here, you’ll find three cron job files corresponding to the next three levels. These are plain ASCII text files.
Open cronjob_bandit23, as it pertains to the level we're working on.

        cd /etc/cron.d
        ls
        cat cronjob_bandit24.sh

Inside, you'll see that it runs a script located at /usr/bin/cronjob_bandit24.sh. Open the file.

        cat /usr/bin/cronjob_bandit24.sh.

*Step 2:* The shell script is designed to periodically execute and then delete all scripts located in /var/spool/bandit24/foo during each run. The key insight is that this behavior can be exploited by placing a custom script in /var/spool/bandit24 that copies the password from /etc/bandit_pass to a user-controlled directory. Therefore, a shell script should be created in a custom directory under /tmp. The goal is to copy the password file from /etc/bandit_pass/bandit24 to a user-controlled location—this time leveraging the cron job to execute the script automatically.

        mkdir /tmp/arnavigator
        cd /tmp/arnavigator
        nano myscript.sh

*Step 3:* The script only needs two essential lines:

        #!/bin/bash
        cat /etc/bandit_pass/bandit24 > /tmp/arnavigator/password.txt

All other lines, such as print/debug statements or variable assignments, are optional and not necessary for the script's functionality. Make sure to set the script as executable using *chmod +x*.

        chmod +x myscript.sh

*Step 4:* Another important step is to ensure that /tmp/<your_directory> is writable by bandit24, as the cron job runs under the bandit24 user. By default, a newly created directory under /tmp is only writable by its owner. To allow bandit24 to write the password file, the directory permissions must be adjusted. For simplicity, this can be done using:

        chmod 777 /tmp/arnavigator
        
This grants read, write, and execute permissions to all users, allowing the script to execute successfully.

*Step 5:* Copy the shell script to /var/spool/bandit24. After placing it there, wait a few minutes. The cron job will pick up the script, execute it, and then delete it. Once executed, the password will be available at /tmp/<your_directory>/<your_file_name> (Use *ls*). Simply read the password file using *cat* to get the next password.

        cat password.txt

### Bandit Level 24 → Level 25
**Key Takeaways**: Learn how to create a brute-forcing script, in conjunction with the nc command. A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

**Approach**:

*Step 1:* The goal is to brute force a 4-digit numeric PIN by sending multiple inputs to the daemon listening on port 30002 using netcat. When the correct combination is sent, the daemon responds with the password for the next level.

To automate this, we first create a file to store all possible 4-digit PINs:

        touch pinlist.txt

*Step 2:* Next, we write a Bash script (brutescript.sh) that generates all PINs from 0000 to 9999 and appends them to the file:

        #!/bin/bash

        for i in $(seq -w 0000 9999); do
            echo "gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i" >> /tmp/arnavbrute/pinlist.txt
        done

*Step 3:* Once the list is ready, we send it to the daemon using netcat:

        cat pinlist.txt | nc localhost 30002

### Bandit Level 25 → Level 26
**Key Takeaways**: Learn more about the intricacies of the more command, as well as the capabilities of a text editor. Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

**Approach**:

*Step 1:* Upon logging into Level 25, we observe that the SSH private key for Bandit26 is available in the current working directory. Logging into Bandit26 using:

        ssh -i bandit26.sshkey bandit26@localhost

is successful but immediately results in the session being terminated.

*Step 2:* A noticeable difference is that the usual login banner or message is absent, and the connection ends right after login. Reviewing the level description reveals a key hint — checking the login shell of Bandit26.

We run the following command to inspect the shell associated with a user:

        getent passwd bandit26 | cut -d: -f7

For bandit24 and bandit25, the shell is */bin/bash*.

For bandit26, it is */usr/bin/showtext*, indicating a custom script is executed instead of a standard shell.

Viewing the contents of */usr/bin/showtext*, we see that it:

* Forces the terminal type to *linux*.

* Displays a file *text.txt* using the *more* command.

* Then exits immediately with *exit 0*.

*Step 3:* The trick lies in abusing the interactive behavior of the more command. If more cannot display the full content of *text.txt* in one screen, it allows user interaction, including the use of the *v* key to launch an editor (typically Vim).

To exploit this:

* Resize the terminal window so that more cannot display the entire *text.txt* file in one screen.

* This enables interaction. Press *v* to open the file in Vim.

* Inside Vim, we cannot modify *text.txt*, but we can spawn a shell.

Run the following commands inside Vim:

        :set shell=/bin/bash
        :shell

This spawns an interactive shell as user bandit26, bypassing the restricted shell script. The :shell command only works because we explicitly set a valid shell using *:set shell=*.

*Step 4:* Once inside the new shell, retrieve the password with:

        cat /etc/bandit_pass/bandit26

### Bandit Level 26 → Level 27
**Key Takeaways**: Revise how a setuid executable works. Good job getting a shell! Now hurry and grab the password for bandit27!

**Approach**:

*Step 1:* We find that there is a file bandit27-do in the working directory after being logged in, and that it is a setuid ELF 32-bit LSB executable. We had previously encountered this in level 19, and the same method is used to solve this level's challenge.

        ./bandit27-do cat /etc/bandit_pass/bandit27

This will return the password to the next level.

### Bandit Level 27 → Level 28
**Key Takeaways**: Learn how to use git commands, specifically the git clone command. There is a git repository at ssh://bandit27-git@localhost/home/bandit27-git/repo. The password for the user bandit27-git is the same as for the user bandit27. Clone the repository and find the password for the next level.

**Approach**:

*Step 1:* Create our own directory within the /tmp directory and clone the git repository to the directory. Go into the *repo* directory, and open the *README* file for the password to the next level.

        mkdir /tmp/arnavgit
        cd /tmp/arnavgit
        git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
        ls
        cd repo
        cat README

This will return the password to the next level.

### Bandit Level 28 → Level 29
**Key Takeaways**: Learn how to use git commands, specifically the git log/checkout/reset command. There is a git repository at ssh://bandit28-git@localhost/home/bandit28-git/repo. The password for the user bandit28-git is the same as for the user bandit28.

**Approach**:

*Step 1:* Create our own directory within the /tmp directory and clone the git repository to the directory. Go into the *repo* directory, and open the *README.md* file (Similar to the previous level).

        mkdir /tmp/arnavgit28
        cd /tmp/arnavgit28
        git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
        ls
        cd repo
        cat README.md

The password in this level appears to be censored.

*Step 2:* A git repository can tell us more about itself through its logs. For this, we can use *git log* to see all the commits that have been made to the repo. 

        git log

*Step 3:* One of the commits appears to have a message saying "add missing data" with it. This suggests that the password might be uncensored in this commit. We can use *git checkout* with the commit hash for finding out the state of the repo at the instance of that commit.

        git checkout fb0df1358b1ff146f581651a84bae622353a71c0

*Step 4:* On reading the *README.md* file, we can see the uncensored password for the next level.

        cat README.md

### Bandit Level 29 → Level 30
**Key Takeaways**: Learn how to use git commands, specifically the git branch and checkout command. There is a git repository at ssh://bandit29-git@localhost/home/bandit29-git/repo. The password for the user bandit29-git is the same as for the user bandit29.

**Approach**:

*Step 1:* Create our own directory within the /tmp directory and clone the git repository to the directory. Go into the *repo* directory, and open the *README.md* file (Similar to the previous level).

        mkdir /tmp/arnavgit29
        cd /tmp/arnavgit29
        git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo
        ls
        cd repo
        cat README.md

The password in this level is not displayed in production, indicating that there might be multiple branches.

*Step 2:* We can see the list of all the branches in the repo using the *git branch* command.

        git branch -a

*Step 3:* All branches can be checked using the *git checkout* command. On checking the remotes/origin/dev branch, we find the password written in the README.md file.

        git checkout remotes/origin/dev 
        cat README.md

### Bandit Level 30 → Level 31
**Key Takeaways**: Learn how to use git commands, specifically the git tags and git show commands. There is a git repository at ssh://bandit30-git@localhost/home/bandit30-git/repo. The password for the user bandit30-git is the same as for the user bandit30.

**Approach**:

*Step 1:* Create our own directory within the /tmp directory and clone the git repository to the directory. Go into the *repo* directory, and open the *README.md* file (Similar to the previous level).

        mkdir /tmp/arnavgit30
        cd /tmp/arnavgit30
        git clone ssh://bandit30-git@localhost:2220/home/bandit30-git/repo
        ls
        cd repo
        cat README.md

The README.md does not have the password at all in this level; just presents a message mocking us.

*Step 2:* There are no other significant branches to checkout as well. One of the crucial features of git is versioning and 'tags' are an important part of it. We can identify versions or commits with tags in git. The command *git tag* displays the list of tags used in the commit.

        git tag

A tag named *secret* is found in the current commit.

*Step 3:* More information about the tag can be found using the *git show* command.

        git show secret
        
This gives us the password to the next level.

### Bandit Level 31 → Level 32
**Key Takeaways**: learn how to use git commands, specifically the git add, commit and push commands, as well as about git files such as .gitignore. There is a git repository at ssh://bandit31-git@localhost/home/bandit31-git/repo. The password for the user bandit31-git is the same as for the user bandit31. Clone the repository and find the password for the next level.

**Approach**:

*Step 1:* Create our own directory within the /tmp directory and clone the git repository to the directory. Go into the *repo* directory, and open the *README.md* file (Similar to the previous level).

        mkdir /tmp/arnavgit31
        cd /tmp/arnavgit31
        git clone ssh://bandit31-git@localhost:2220/home/bandit31-git/repo
        ls
        cd repo
        cat README.md

The README.md does not have the password, but instructs us to add a file named *key.txt* to the repo.

*Step 2:* Create a file named *key.txt* and enter the given message in it. On adding the file using *git add*, we see that the *.gitignore* file denies the ability to add any text files to the repo. We need to modify the *.gitignore* file to remove the line "*.txt". We can finally add the file now. Use *git commit* with a message, and finally push the file with origin "master". *git status* can be used at any point to know the current status of git.

        git add key.txt
        git commit -m "Added key.txt"
        git push origin master
        
Following these steps will result in the repo displaying a banner with mutiple terminal outputs and a "Well done!" message with the password to the next level.
