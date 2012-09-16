NOTE: This is still very much a work in progress, and not all functionality is yet 
implemented.  I will update this readme with a link to the blogpost regarding this.
It is also worth mentioning that all output beginning with [dbg] are, in fact, 
debug statements.  They will be removed once I near a more defined release.

#[ZARP]
###:Version 0.02
###:Network Attack Tool
###:@ballastsec, @dronesec

#[INTRODUCTION]
<pre>
Zarp is a network attack tool centered around exploitation of local networks.  This does not 
include system exploitation, but rather abusing networking protocols and stacks to take 
over, infiltrate, and knock out.  Sessions can be managed to quickly poison and sniff multiple 
systems at once, dumping sensitive information automatically or to the attacker directly.  
Various sniffers are included to automatically parse usernames and passwords from various 
protocols, as well as view HTTP traffic and more.  DoS attacks are included to knock out 
various systems and applications.  These tools open up the possibility for very complex attack 
scenarios on live networks quickly, cleanly, and quietly.
</pre>
#[TOOL OVERVIEW] 
<pre>
	[POISONERS]
	Various man in the middle tools provide a stepping stone for more complex attacks.
	: ARP, DNS, DHCP :

	[DOS]
	Denial of service tools for rendering various systems unusable.
	: Teardrop, IPv6 NDP RA, Nestea, LAND, TCP SYN, SMB2 :

	[SNIFFERS]
	Post-poisoning tools for aggressively parsing and sniffing local traffic.  These are 
	used to intelligently view poisoned traffic.
	: HTTP Traffic, Password and Username Sniffer :

	[SCANNERS]
	These tools can be used for mapping a network out.  Network topography and service 
	systems can be automatically mapped out to assist in the planning of attacks.
	: Network Scanner, Service Scanner, Access Point Scanner :
	
	[EMULATE]
	These are functionally different from poisoners in that they provide a spoofed 
	service.  For example, you could set up a fake SSH service or a honeypot FTP server 
	and poison a systems DNS to redirect to yours.  When you get a hit, remove the DNS 
	poison and allow it to resolve correctly.
	: Spoof HTTP Server, Spoof SSH Server :
	
	[PARAMETER]
	Parameter tools are for use when you're on the outside of a network.  These will 
	assist in mapping out potential entry points and soft spots for vulnerabilities.  
	These, in conjunction with Scanners, should give you a solid picture of what's 
	available.  
	: WEP Crack, WPA2 Crack, Router pwn : 
</pre>
#[USE EXAMPLES]
## Command line options
<pre>
bryan@devbox:~/zarp$ sudo python zarp.py -h
Usage: zarp.py [options]

Options:
  -h, --help  show this help message and exit
  -s SCAN     Quick network map
  --finger    Fingerprint scan packets
  -a          Service scan
  -q FILTER   Quick network sniff with filter
  -w ADAPTER  Wireless AP scan
bryan@devbox:~/zarp$ 
</pre>
## Main menu
<pre>
bryan@devbox:~/zarp$ sudo python zarp.py
	        [ZARP]		
	    [Version 0.02]			
	[1] Poisoners 	 [2] DoS Attacks
	[3] Sniffers 	 [4] Scanners
	[5] Parameter 	 [6] Sessions

0) Back
> 
</pre>
## ARP Poisoning Session
<pre>
	[1] ARP Poison
	[2] DNS Poison
	[3] DHCP Poison

0) Back
> 1
[dbg] Received module start for:  arp
[!] Using interface [eth2:08:00:27:2d:7a:6d]
[!] Enter host to poison:	192.168.1.88
[!] Enter address to spoof:	192.168.1.1
[!] Spoof IP 192.168.1.88 from victim 192.168.1.1.  Is this correct? y
[!] Initializing ARP poison..
	[1] ARP Poison
	[2] DNS Poison
	[3] DHCP Poison

0) Back
> 0
	        [ZARP]		
	    [Version 0.02]			
	[1] Poisoners 	 [2] DoS Attacks
	[3] Sniffers 	 [4] Scanners
	[5] Parameter 	 [6] Sessions

0) Back
> 6

	[Running sessions]
[!] ARP POISONS [arp]:
	[0] 192.168.1.88


	[1] Stop session
	[2] View session
	[3] Start session logger
	[4] Stop session logger

0) Back
> 
</pre>
