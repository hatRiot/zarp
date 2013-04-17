import util
import socket
from scapy.all import *
from threading import Thread
from ..sniffer.sniffer import Sniffer

""" Much like the passive scanner in Ettercap,
	this module was designed to passively map the network
	without spewing packets.  This will take some
	time, as we can only sniff what's coming at us.  One 
	packet is sent out, and that's for rDNS.  

	Implemented as a sniffer since that's technically what
	we're doing with it.
"""
class Address:
	def __eq__(self, other):
		return self.ip == other

	def __init__(self):
		self.ip   = None
		self.mac  = None
		self.host = None

class passive_scan(Sniffer):
	def __init__(self):
		super(passive_scan, self).__init__('Passive Scanner')
		self.netmap = []

	def initialize(self):
		util.Msg('Initializing passive network map...')
		self.source = 'Passive Scanner'    # for session view
		self.sniff_filter = 'arp'          # pick out arp packets
		self.run()
		return 'Passive Scanner'
	
	def resolve(self,ip):
		"""rdns with a timeout"""
		socket.setdefaulttimeout(2)
		try:
			host = socket.gethostbyaddr(ip)
		except:
			host = None
		if not host is None: host = host[0]
		return host

	def dump(self, pkt):
		""" Fish out broadcast packets and get src/dst
		"""
		if 'ARP' in pkt:
			if pkt[ARP].op == 1:
				psrc = pkt[ARP].psrc
				if not psrc in self.netmap:
					addr = Address()
					addr.ip   = psrc
					addr.mac  = pkt[ARP].hwsrc
					addr.host = self.resolve(psrc) 
					self.netmap.append(addr)
			elif pkt[ARP].op == 2:
				pdst = pkt[ARP].pdst
				if not pdst in self.netmap:
					addr = Address()
					addr.ip    = pdst
					addr.mac   = pkt[ARP].hwdst
					addr.host  = self.resolve(pdst)
					self.netmap.append(addr)

	def view(self):
		"""Overridden Sniffer view
		   since we just need to dump info 
		   out
		"""
		if len(self.netmap) <= 0:
			util.Msg("No hosts yet mapped.")
		else:
			for address in self.netmap:
				print '\t%s\t%s\t%s'%(address.ip,address.mac,address.host)
