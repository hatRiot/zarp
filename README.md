Introduction
==

Zarp is a network attack tool centered around the exploitation of local networks. This does not include system exploitation, but rather abusing networking protocols and stacks to take over, infiltrate, and knock out. Sessions can be managed to quickly poison and sniff multiple systems at once, dumping sensitive information automatically or to the attacker directly. Various sniffers are included to automatically parse usernames and passwords from various protocols, as well as view HTTP traffic and more. DoS attacks are included to knock out various systems and applications. These tools open up the possibility for very complex attack scenarios on live networks quickly, cleanly, and quietly.

The long-term goal of zarp is to become the master command center of a network; to provide a modular, well-defined framework that provides a powerful overview and in-depth analysis of an entire network.  This will come to light with the future inclusion of a web application front-end, which acts as the television screen, whereas the CLI interface will be the remote.  This will provide network topology reports, host relationships, and more.  zarp aims to be your window into the potential exploitability of a network and its hosts, not an exploitation platform itself; it is the manipulation of relationships and trust felt within local intranets.  Look for zeb, the web-app frontend to zarp, sometime in the future.

Current version: 1.5 
Current dev version: 1.6 

Installation
==
zarp is intended to be as dependency-free as possible.  When available, zarp has opted to use pure or native Python implementations over requiring or importing huge libraries.  Even as such, zarp requires the following to run:

* Linux 
* Python 2.7.x 
* Scapy (packaged with zarp) 

It is also recommended that user's have the following installed for access to specific modules:

* airmon-ng suite (for all your wireless cracking needs)
* tcpdump
* libmproxy (packaged with zarp)
* paramiko (SSH service)
* nfqueue-bindings (packet modifier)

The recommended installation process is to run:

```
git clone git://github.com/hatRiot/zarp.git

pip install -r requirements.txt
```

You can then run:

```
sudo python zarp.py --update
```

to update zarp.  The update flag will not work if you download the tarball from the Git page.

Scapy comes packaged with Zarp and no installation is required. Wifite is used for wireless AP cracking; a specific version (ballast-dev branch) is required. This comes packaged with zarp. There are some dependencies required for Scapy, but most should be pretty easy to install or already be installed.

Tool Overview
==
Broad categories are (see wiki for more information on these):
* Poisoners
* Denial of Service
* Sniffers
* Scanners
* Services
* Parameter
* Attacks

CLI Usage and Shortcuts
==
```
> help

  zarp options:
    help            - This menu
    opts            - Dump zarp current settings
    exit            - Exit immediately
    bg          - Put zarp to background
    set [key] [value]   - Set key to value

  zarp module options:
    [int] [value]       - Set option [int] to value [value]
    [int] o         - View options for setting
    run (r)         - Run the selected module
    info            - Display module information

```

Modules can be navigated to by nesting entries:
```
bryan@debdev:~/tools/zarp$ sudo ./zarp.py 
[!] Loaded 34 modules.
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)  [Version: 0.1.5]

    [1] Poisoners       [5] Parameter
    [2] DoS Attacks     [6] Services 
    [3] Sniffers        [7] Attacks  
    [4] Scanners        [8] Sessions 

0) Back
> 6 2
    +-----+----------------+----------------------------+------+----------+-
    |     | Option         | Value                      | Type | Required | 
    +-----+----------------+----------------------------+------+----------+-
    | [1] | Displayed MOTD | b4ll4stS3c FTP Server v1.4 | str  | False    | 
    +-----+----------------+----------------------------+------+----------+-
    | [2] | Listen port    | 21                         | int  | False    | 
    +-----+----------------+----------------------------+------+----------+-
0) Back
FTP Server > 
```
Nested entries go as far as modules will.  Note that right now it's 'dumb' in that, if you enter in a ton of numbers, it's going to continue dumping that out as module selection!

Usage Examples
==
List of modules accessible from the command line:
```
bryan@debdev:~/tools/zarp$ sudo ./zarp.py --help
[!] Loaded 34 modules.
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)  [Version: 0.1.5]

usage: zarp.py [-h] [-q FILTER] [--update] [--wap] [--ftp] [--http] [--smb]
               [--ssh] [--telnet] [-w] [-s] [--service-scan]

optional arguments:
  -h, --help      show this help message and exit
  -q FILTER       Generic network sniff
  --update        Update Zarp

Services:
  --wap           Wireless access point
  --ftp           FTP server
  --http          HTTP Server
  --smb           SMB Service
  --ssh           SSH Server
  --telnet        Telnet server

Scanners:
  -w              Wireless AP Scan
  -s              Network scanner
  --service-scan  Service scanner
bryan@debdev:~/tools/zarp$ 
```

Main menu when launched with the command line GUI:
```
bryan@devbox:~/zarp$ sudo ./zarp.py
[!] Loaded 33 modules.
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)
        [Version 0.1.4]         
    [1] Poisoners       [5] Parameter
    [2] DoS Attacks     [6] Services 
    [3] Sniffers        [7] Attacks  
    [4] Scanners        [8] Sessions 

0) Back
> 
```

Navigating a module is pretty simple, and there are really only a few commands to know.  When in the context of a module, the command 'info' can be used to dump a help or informational string:
```
ARP Spoof > info
--------------------------------------------------------- 
The heart and soul of zarp.  This module exploits the ARP
protocol to redirect all traffic through the attacker's 
chosen system. 

http://en.wikipedia.org/wiki/ARP_poison
---------------------------------------------------------
    +-----+------------------------------------+-------+------+----------+-
    |     | Option                             | Value | Type | Required | 
    +-----+------------------------------------+-------+------+----------+-
    | [1] | Interval to send respoofed packets | 2     | int  | False    | 
    +-----+------------------------------------+-------+------+----------+-
    | [2] | Address to spoof from target       | None  | ip   | True     | 
    +-----+------------------------------------+-------+------+----------+-
    | [3] | Target to poison                   | None  | ip   | True     | 
    +-----+------------------------------------+-------+------+----------+-
0) Back
ARP Spoof > 
```

To set an option, give it the option number followed by the value:
```
ARP Spoof > 2 192.168.1.219
```

If an option supports a choice list, give it the option number followed by the lowercase letter o:
```
HTTP Sniffer > 2 o
[!] Options: ['Site Only', 'Request String', 'Request and Payload', 'Session IDs', 'Custom Regex']
    +-----+-----------------------------+--------------+-------+----------+-
    |     | Option                      | Value        | Type  | Required | 
    +-----+-----------------------------+--------------+-------+----------+-
    | [1] | Regex for level 5 verbosity | None         | regex | False    | 
    +-----+-----------------------------+--------------+-------+----------+-
    | [2] | Output verbosity            | 1            | int   | False    | 
    +-----+-----------------------------+--------------+-------+----------+-
    | [3] | Address to sniff from       | 192.168.1.97 | ip    | False    | 
    +-----+-----------------------------+--------------+-------+----------+-
0) Back
HTTP Sniffer > 
```

Modules, once all required options are set, can be run by specifying a lowercase '''r'''.

Future/Current Development
==

Moved to freedcamp; please send me an email if you'd like to contribute.
