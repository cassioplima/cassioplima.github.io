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

### Scanning

+ _nmap_
       
### Enumeration

+ _Browsing HTTP server_
+ _Directory Scanning using dirb_

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

#### I've used the dirb to enumerate directories, but dirbuster and gobuster would work too. We see that the dirb found some pages, that's good. But the page what we interested to is `/phpmyadmin`

![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/Captura%20de%20tela%20em%202019-11-10%2002-19-10.png)

