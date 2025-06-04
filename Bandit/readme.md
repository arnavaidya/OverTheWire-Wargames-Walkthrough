# Bandit Walkthroughs

## Level 0 ➝ Level 1

**Description**: Connect to the game using SSH to access the Bandit server.

**Steps**:

Open your terminal.

1. Connect using SSH:

        ssh -p 2220 bandit0@bandit.labs.overthewire.org 

2. Enter the password when prompted:

        bandit0

3. Once logged in, read the password for the next level:

        cat readme

4. Save the password shown — it will be used for Level 1.

## Level 1 ➝ Level 2

**Description**: The password for the next level is stored in a file called -, which is a tricky filename.

**Steps**:

1. Login as bandit1 using the password from Level 0:

        ssh -p 2220 bandit1@bandit.labs.overthewire.org 
   
2. Read the file named - using:

        cat ./-
   
3. Copy the password displayed for Level 2.

## Level 2 ➝ Level 3

**Description**: The password for the next level is stored in a file called "spaces in this filename", which is a tricky filename.

**Steps**:

1. Login as bandit2 using the password from Level 1:

        ssh -p 2220 bandit2@bandit.labs.overthewire.org 
   
2. Read the file named - using:

        cat "spaces in this filename"
   
3. Copy the password displayed for Level 3.

## Level 3 ➝ Level 4

**Description**: The password for the next level is stored in a hidden file in the inhere directory.

**Steps**:

1. Login as bandit3 using the password from Level 2:

        ssh -p 2220 bandit3@bandit.labs.overthewire.org 

2. Change the pwd to "inhere".
           
        cd inhere
   
3. Use find to search for hidden files inside inhere:

        find -L
   
5. Read the content of the found file:

        cat ./...Hiding-From-You

6. Copy the password displayed — it’s for Level 4.

## Level 4 ➝ Level 5

**Description**: The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.

**Steps**:

1. Login as bandit4 using the password from Level 3:

        ssh -p 2220 bandit4@bandit.labs.overthewire.org 

2. Change the pwd to "inhere".
           
        cd inhere
   
3. Use find to search for hidden files inside inhere:

        ls -a
   
5. Check file type for each file in the directory using "file" command:

        file ./-file*

6. Open the file with the type "ASCII text".

        cat ./-file07
 
7. Copy the password displayed — it’s for Level 5.

# Level 5 ➝ Level 6

**Description**: The password for the next level is stored in a human-readable file in the inhere directory, not executable, 1033 bytes in size, and only one such file exists.

**Steps**:

1. Login as bandit4 using the password from Level 3:

        ssh -p 2220 bandit5@bandit.labs.overthewire.org

2. Find the target file using the find command:

        find inhere -type f -size 1033c ! -executable

Explanation:

        find – the command-line utility used to search for files and directories.

        inhere – the directory where the search is performed.

        -type f – restricts the search to regular files (not directories, symlinks, etc.).

        -size 1033c – looks for files that are exactly 1033 bytes in size.

        c means bytes (you could also use k for kilobytes, M for megabytes, etc.)

        ! -executable – filters out executable files, meaning it will only return files that are not executable.
        This helps ensure you're dealing with plain text or human-readable files.
4. Read the contents of the file (replace the path with the exact file found):

        cat ./maybehere07/.file2
   
6. Save the password shown — it will be used for Level 6.
