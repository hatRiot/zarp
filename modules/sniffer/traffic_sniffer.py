import util
from sniffer import Sniffer
from scapy.all import *
from threading import Thread

#
# Simple sniffer for dumping host traffic; mainly for debug
#
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

				self.sniff = True
				sniff_thread = Thread(target=self.traffic_sniffer)
				sniff_thread.start()

				break
			except KeyboardInterrupt:
				return	
			except Exception, j:
				util.Error('Error with sniffer: %s'%j)	
				return	
		return self.source 

	# sniff traffic
	def traffic_sniffer(self):
		sniff(filter='src %s or dst %s'%(self.source, self.source), store=0, prn=self.dump, stopper=self.stop_callback, stopperTimeout=3)

	# just dump the data and print the summary
	def dump(self, pkt):
		if self.dump_data and not pkt is None:
			print pkt.summary()
		if self.log_data:
			self.log_file.write(pkt.summary()+'\n')
