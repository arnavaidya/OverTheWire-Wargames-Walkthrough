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
