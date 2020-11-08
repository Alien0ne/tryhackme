
```
Task 1 : Flags

	1) user.txt
	THM{Sh3llSh0ck_r0ckz}

	2)root.txt
	THM{g00d_j0b_0day_is_Pleased}

```

* checked for open ports
	Open Ports: 22,80


* checked the website and the directories

	### http://10.10.49.1/
		- Nothing useful 
	### http://10.10.49.1/robots.txt
		- You really thought it'd be this easy?
	### http://10.10.49.1/secret/
		- Found a turtle image
	### http://10.10.49.1/backup
		-Found a rsa private key 
	### http://10.10.49.1/cgi-bin/test.cgi
		-Hello World!


* after running nikto , nikto gave me something useful 
	+ OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).


* searched for an exploit in metasploit 
	got a shell using the metasploit module
	exploit/multi/http/apache_mod_cgi_bash_env_exec    2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)


* using linpeas i got to knew about the linux version is outdated


* searched for the linux version based exploits
	- https://www.exploit-db.com/exploits/37292

 

* using the exploit got the root user

