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

**Commands**:

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

