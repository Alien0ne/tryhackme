# Walkthrough 


## Task 1 : Deploy

### 1) Connect to our network by going to your access page. This is important as you will not be able to access the machine without connecting!
### >A) No Answer Needed


### 2) Deploy the machine by clicking the green "Deploy" button on this task and access its webserver.
### > No Answer Needed



## Task 2 :  Cookies


- Cookies are a small piece of data which are sent from the webiste and stored on the user computer 
- These cookies helps in session management , personalization , tracking .


### 1) On the deployed Avengers machine you recently deployed, get the flag1 cookie value.
### >A) cookie_secrets




## Task 3 : HTTP Headers


- HTTP Headers let a client and server pass information with a HTTP request or response. Header names and values are separated by a single colon and are integral part of the HTTP protocol.
- The main two HTTP Methods are POST and GET requests. The GET method us used to request data from a resource and the POST method is used to send data to a server.
- You can find the headers in the web browser by opening the developer tools and navigating to the networktab
- You need to refresh the page to see the headers

### 1) Look at the HTTP response headers and obtain flag 2.
### >A) headers_are_important




## Task 4 : Enumeration and FTP


- Scan for the open ports 

```
kali@kali:~/Desktop/thm/avengers-blog$ cat scan.txt
[*] OS based on TTL
Linux
[*] Full TCP Scan
Open ports: 22,21,80
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d8:52:77:a2:bc:18:e8:3f:52:e5:d1:a5:20:74:7a:9d (RSA)
|   256 52:60:6b:6c:2e:52:4e:a5:54:29:92:85:27:4e:ef:5a (ECDSA)
|_  256 91:48:53:de:54:0b:a6:be:20:18:23:ae:71:11:19:e0 (ED25519)
80/tcp open  http    Node.js Express framework
|_http-title: Avengers! Assemble!
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

- We see that the FTP port is open 
- Connect to the FTP poet using the creds given in the room
- user : groot
- password : iamgroot
- To connect to the FTP use this Command `ftp $IP` and provide the username and password 

```
kali@kali:~/Desktop/thm/avengers-blog$ ftp 10.10.162.99
Connected to 10.10.162.99.
220 (vsFTPd 3.0.3)
Name (10.10.162.99:kali): groot
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Oct 04  2019 files
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0              33 Oct 04  2019 flag3.txt
226 Directory send OK.
ftp> get flag3.txt
local: flag3.txt remote: flag3.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for flag3.txt (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (226.9476 kB/s)
ftp> exit
221 Goodbye.
kali@kali:~/Desktop/thm/avengers-blog$ cat flag3.txt
8fc651a739befc58d450dc48e1f1fd2e
kali@kali:~/Desktop/thm/avengers-blog$ 

```


### 1) Look around the FTP share and read flag 3!
### A) 8fc651a739befc58d450dc48e1f1fd2e



## Task 5 : GoBuster


- Gobuster is a tool used for directory dicovery 
- Gobuster bruteforce all the directories and give the reponse code of it 


```
kali@kali:~/Desktop/thm/avengers-blog$ gobuster
Usage:
  gobuster [command]

Available Commands:
  dir         Uses directory/file brutceforcing mode
  dns         Uses DNS subdomain bruteforcing mode
  help        Help about any command
  vhost       Uses VHOST bruteforcing mode

Flags:
  -h, --help              help for gobuster
  -z, --noprogress        Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist

Use "gobuster [command] --help" for more information about a command.

```

### 1) What is the directory that has an Avengers login?

### A) /portal

```
kali@kali:~/Desktop/thm/avengers-blog$ gobuster dir -u 10.10.162.99/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.162.99/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/19 18:50:38 Starting gobuster
===============================================================
/Home (Status: 302)
/assets (Status: 301)
/css (Status: 301)
/home (Status: 302)
/img (Status: 301)
/js (Status: 301)
/logout (Status: 302)
/portal (Status: 200)
===============================================================
2020/11/19 18:53:18 Finished
===============================================================
kali@kali:~/Desktop/thm/avengers-blog$ 

```




## Task 6 :  SQL Injection


- SQL Injection is a code injection technique that manipulates an SQL query. You can execute you're own SQL that could destroy the database, reveal all database data (such as usernames and passwords) or trick the web server in authenticating you.
- To exploit SQL, we first need to know how it works.
- A SQL query could be `SELECT * FROM Users WHERE username = {User Input} AND password = {User Input 2}`, if you insert additional SQL as the {User Input} we can manipulate this query. For example, if I have the {User Input 2} as `' 1=1` we could trick the query into authenticating us as the `'` character would break the SQL query and `1=1` would evaluate to be true.
- To conclude, having our first {User Input} as the username of the account and {User Input 2} being the condition to make the query true, the final query would be:``` SELECT * FROM Users WHERE username = `' 1=1` AND password = `' 1=1` ```
- This would authenticate us as the admin user.


### 1) Log into the Avengers site. View the page source, how many lines of code are there?
### A) 223




## Task 7 : Remote Code Execution and Linux


### 1) Read the contents of flag5.txt 
### A) d335e2d13f36558ba1e67969a1718af7


- In the portal we can run system commands and i see that only some commands are executable 
- i tried to get a reverse-shell using pentestmoney shells but that did not work 
- so i tried to get the flag from the portal only 
- i tried to cat the flag but that also did not work 
- We can read files in linux using one more command other than cat i.e `less`
- Then i used this command to get the flag 

```cd ..;less flag5.txt ```

