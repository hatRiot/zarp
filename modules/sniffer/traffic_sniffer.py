from util import Error
from sniffer import Sniffer
from scapy.all import *

#
# Simple sniffer for dumping host traffic
#
__name__ = 'Traffic Sniffer'
class TrafficSniffer(Sniffer):
	def __init__(self):
		super(TrafficSniffer, self).__init__('Traffic')
	
	# init
	def initialize(self):
		while True:
			try:
				tmp = raw_input('[!] Sniff traffic from %s.  Is this correct? '%self.source)
				if 'n' in tmp.lower():
					break	
				
				self.sniff_filter = "src {0} or dst {0}".format(self.source)
				self.sniff = True
				self.sniff_thread.start()
				break
			except KeyboardInterrupt:
				return	
			except Exception, j:
				Error('Error with sniffer: %s'%j)	
				return	
		return self.source 

	# just dump the data and print the summary
	def dump(self, pkt):
		if not pkt is None:
			self.log_msg(pkt.summary())
