# Various tips

## Vim

#### How to convert the ^M linebreak to 'normal' linebreak in vim

```vim
:set fileformat=unix
```

## Man

1. User-level commands and applications
2. System calls and kernel error codes
3. Library calls
4. Device drivers and network protocols
5. Standard file formats
6. Games and demonstrations
7. Miscellaneous files and documents
8. System administration commands
9. Obscure kernel specs and interfaces

`man sync` gets you the man page for the sync command, and `man 2 sync` gets you the man page for the sync system call.

`man -k keyword` or `apropos keyword` prints a list of man pages that have keyword in their one-line synopses.

## Bash

use <**Alt-\[0-9]> \<Alt-.**> to repeat the nth arg (0 is command) \<Alt-.> again to repeat the nth arg

With bash, use -x to echo commands before they are executed and -n to check commands for syntax without executing them.

To redirect both STDOUT and STDERR to the same place, use the >& symbol. To redirect STDERR only, use 2>.

#### convert binary to int&#x20;

```
echo "$((2#00011000))"
```

## Printing

The `lpr` command transmits copies of the files to the CUPS server Most changes require jobs to be identified by their job number, which you can get from `lpq`. For example, to remove a print job, just run `lprm jobid`. `lpstat -t` summarizes the print server’s overall status. telling CUPS to use a particular default for your account `lpoptions -dprinter_name`

## Network

```shell
nmcli dev wifi connect SSID password PASSWORD
```

Prioritize a connection among multiple ones

```shell
sudo ifmetric enp0s20f0u2 50
```

## Bluetooth

Connect to a Bluetooth device from command line in Ubuntu Linux

```bash
hcitool scan  # to get the MAC address of your device
bluetoothctl
agent on
scan on  # wait for your device's address to show up here
scan off
trust MAC_ADDRESS
pair MAC_ADDRRESS
connect MAC_ADDRESS
```

## Brightness

```shell
echo 500 | sudo tee /sys/class/backlight/intel_backlight/brightness
```

## Docker

#### **Run git in docker**

```bash
docker run -ti --rm -v $HOME/.ssh:/root/.ssh:ro \
    -v $(pwd):/repository \
    -w /repository \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    --user $(id -u):$(id -g) \
    -e GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no" \
    --entrypoint "" alpine/git /bin/sh
```
