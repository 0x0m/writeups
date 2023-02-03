We start out with a basic recon nmap scan. This reveals that there's an http and ssh service. Trying an anonymous logon to ssh doesn't work.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -sV -sC -T4 -p- -oN tcp.nmap 10.10.10.210
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-29 00:57 EST
Nmap scan report for 10.10.10.210
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 87:e3:d4:32:cd:51:d2:96:70:ef:5f:48:22:50:ab:67 (RSA)
|   256 27:d1:37:b0:c5:3c:b5:81:6a:7c:36:8a:2b:63:9a:b9 (ECDSA)
|_  256 7f:13:1b:cf:e6:45:51:b9:09:43:9a:23:2f:50:3c:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/29%OT=22%CT=1%CU=40178%PV=Y%DS=2%DC=T%G=Y%TM=63D60C4
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST1
OS:1NW7%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   151.73 ms 10.18.0.1
2   151.90 ms 10.10.10.210

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 394.93 seconds
```


Checking the website, there's only a default template page. But looking at the headers reveals a domain.

[](./images/1.png)

```
┌──(kali㉿kali)-[~]
└─$ curl -v 10.10.56.149       
*   Trying 10.10.56.149:80...
* Connected to 10.10.56.149 (10.10.56.149) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.56.149
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 30 Jan 2023 00:41:11 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Sun, 17 Apr 2022 18:54:09 GMT
< ETag: "2aa6-5dcde2b3f2ff9"
< Accept-Ranges: bytes
< Content-Length: 10918
< Vary: Accept-Encoding
< X-Backend-Server: seasurfer.thm
< Content-Type: text/html
< 
[...]
```
