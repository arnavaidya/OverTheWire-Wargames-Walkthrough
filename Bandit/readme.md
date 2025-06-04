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
