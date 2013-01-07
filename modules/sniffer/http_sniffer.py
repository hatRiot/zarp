import stream 
import util
from sniffer import Sniffer
from threading import Thread
from scapy.all import *

#
# Module sniffs incoming traffic for any HTTP traffic and dumps it.
#
class HTTPSniffer(Sniffer):
	def __init__(self):
		super(HTTPSniffer,self).__init__('HTTP sniffer')

	#
	# Sniffs for HTTP traffic by checking the destination port (for now)
	# TODO: https
	#
	def traffic_sniffer(self):
		sniff(filter="tcp and dst port 80 and src %s"%self.source, store=0, prn=self.dump, 
						stopper=self.stop_callback,stopperTimeout=3)
	#
	# initialize the sniffer by getting the source address from the user
	#
	def initialize(self):
		self.source = raw_input('[!] Enter address to listen for HTTP packets from: ')
		tmp = raw_input('[!] Sniff HTTP traffic from %s.  Is this correct? '%self.source)
		if tmp == "n":
			return None
		self.sniff = True
		sniff_thread = Thread(target=self.traffic_sniffer)
		sniff_thread.start()
		return self.source

	#
	# dump the HTTP payload to the screen IF they're viewing the session
	#
	def dump(self, pkt):
		try:
			if pkt.haslayer(Raw):
				if self.dump_data:
					print pkt.getlayer(Raw).load
				if self.log_data:
					self.log_file.write(str(pkt.getlayer(Raw).load))	
		except KeyboardInterrupt:
			self.dump_data = False
			return
