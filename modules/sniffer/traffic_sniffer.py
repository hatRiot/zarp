from scapy.all import *
from threading import Thread
import util

#
# Simple sniffer for dumping host traffic; mainly for debug
#
class TrafficSniffer:
	def __init__(self):
		self.sniff = False
		self.source = None
		self.dump_data = False
		self.log_data = False
		self.log_file = None
	
	# init
	def initialize(self):
		srs = None
		while True:
			try:
				self.source = raw_input('[!] Enter address to sniff: ')
				tmp = raw_input('[!] Sniff traffic from %s.  Is this correct? '%self.source)
				if 'n' in tmp.lower():
					break	

				self.sniff = True
				sniff_thread = Thread(target=self.traffic_sniffer)
				sniff_thread.start()

				srs = self.source
				break
			except KeyboardInterrupt:
				srs = None
				break
			except Exception, j:
				print j
				continue
		return srs

	# sniff traffic
	def traffic_sniffer(self):
		sniff(filter='src %s or dst %s'%(self.source, self.source), store=0, prn=self.dump, stopper=self.stop_callback, stopperTimeout=3)

	# just dump the data and print the summary
	def dump(self, pkt):
		if self.dump_data and not pkt is None:
			print pkt.summary()

	# shutdown sniffer			
	def shutdown(self):
		if self.sniff:
			self.sniff = False
		util.debug('Traffic sniffer shutting down.')
		return True

	# stopper callback
	def stop_callback(self):
		if self.sniff:
			return False
		util.debug('Traffic sniffer shutdown')
		return True

	# dump traffic
	def view(self):
		try:
			util.Msg('Dumping traffic...')
			while True:
				self.dump_data = True
		except KeyboardInterrupt:
			self.dump_data = False
			return
