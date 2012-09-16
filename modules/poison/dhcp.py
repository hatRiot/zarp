import stream
import logging
from threading import Thread
from scapy.all import *

#
# Set up a rogue DHCP server and hand out IP addresses.
#
class DHCPSpoof:
	def __init__(self):
		self.local_mac = get_if_hwaddr(conf.iface)
		self.spoofed_hosts = []
		self.running = False
		self.gateway = None
		self.dns = None
		self.net_mask = None

	def initialize(self):
		try:
			self.gateway = raw_input('[!] Enter (spoofed) gateway: ')
			self.dns = raw_input('[!] Enter DNS: ')
			self.net_mask = raw_input('[!] Enter netmask to hand IPs out from: ')
			tmp = raw_input('[!] Forward all traffic to %s.  Use %s for DNS.  Assign IP\'s from %s.  Is this correct? '%(self.gateway,self.dns,self.net_mask))
			if tmp == 'n':
				return False
			print '[+] Configuring rogue DHCP server..'
			thread = Thread(target=self.netsniff)
			thread.start()
			self.running = True
			return True
		except Exception, j:
			print '[-] Error: ', j
			return False
	
	#
	#
	#
	def netsniff(self):
		sniff(prn=self.pkt_handler,store=0,stopper=self.test_stop,stopperTimeout=5)

	#
	#
	#
	def pkt_handler(self, pkt):
		# first test if this is a DHCPREQ
		if self.running and DHCP in pkt:
			print '[-] Rogue DHCP caught DHCP packet.'			
		# not DHCP, might be something we need to forward

	#
	#
	#
	def test_stop(self):
		if self.running:
			return False
		print '[dbg] stopping dhcp threads'
		return True

	#
	#
	#
	def shutdown(self):
		self.running = False
		print '[!] DHCP server shutdown.'
