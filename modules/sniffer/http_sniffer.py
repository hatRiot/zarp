import stream 
import util
from sniffer import Sniffer
from re import findall
from threading import Thread
from scapy.all import *

#
# Module sniffs incoming traffic for any HTTP traffic and dumps it.
#
class HTTPSniffer(Sniffer):
	def __init__(self):
		self.verbs = [ 'Site Only', 'Request String', 'Request and Payload' ]
		self.verb = 0
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

		while True:
			try:
				util.Msg('Enter verbosity level: ')
				for i in range(1, len(self.verbs)+1):
					print '\t[%d] %s'%(i, self.verbs[i-1])
				self.verb = int(raw_input('> ')) - 1

				if self.verb >= len(self.verbs): 
					util.Error('Input incorrect.')
					continue
				break
			except KeyboardInterrupt:
				return
			except:
				pass

		util.Msg('Output dumping in \'%s\' verbosity.'%self.verbs[self.verb])
		tmp = raw_input('[!] Sniff HTTP traffic from %s.  Is this correct? '
						%(self.source))

		if 'n' in tmp.lower(): 
			return None
		self.sniff = True
		sniff_thread = Thread(target=self.traffic_sniffer)
		sniff_thread.start()
		return self.source
	
	#
	# format output as per verb level 
	#
	def pull_output(self, pkt):
		data = None
		if self.verb is 1:
			# parse the site only
			payload = pkt.getlayer(Raw).load
			data = findall('Host: (.*)', payload)[0]
		elif self.verb is 2:
			payload = pkt.getlayer(Raw).load
			data = payload.split('\n')[0]
		elif self.verb is 3:
			data = pkt.getlayer(Raw).load
		return data

	#
	# dump the formatted payload 
	#
	def dump(self, pkt):
		try:
			if pkt.haslayer(Raw):
				if self.dump_data or self.log_data:
					data = self.pull_output(pkt)
					if self.dump_data:
						print data
					if self.log_data:
						self.log_file.write(data)
		except KeyboardInterrupt:
			self.dump_data = False
			return
