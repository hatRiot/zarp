import stream
import util
import re
from sniffer import Sniffer
from scapy.all import *

class http_sniffer(Sniffer):
	"""HTTP sniffer that allows various verbosity levels
	"""
	def __init__(self):
		self.verbs = [ 'Site Only', 'Request String', 'Request and Payload',
					   'Custom Regex' ]
		self.verb = 0
		self.regex = None
		super(http_sniffer,self).__init__('HTTP Sniffer')

	def initialize(self):
		"""Initialize the sniffer"""
		self.get_ip()
		while True:
			try:
				util.Msg('Enter verbosity level: ')
				for i in range(1, len(self.verbs)+1):
					print '\t[%d] %s'%(i, self.verbs[i-1])
				self.verb = int(raw_input('> ')) - 1

				if self.verb >= len(self.verbs): 
					util.Error('Input incorrect.')
					continue

				if self.verb is 3:
					self.regex = raw_input('[!] Enter regex: ')
					self.regex = re.compile(self.regex)
				break
			except KeyboardInterrupt:
				return
			except Exception, j:
				print type(j)
				pass

		util.Msg('Output dumping in \'%s\' verbosity.'%self.verbs[self.verb])
		tmp = raw_input('[!] Sniff HTTP traffic from %s.  Is this correct? '
						%(self.source))

		if 'n' in tmp.lower(): 
			return None

		self.sniff_filter = "tcp and dst port 80 and src %s"%self.source
		self.run()
		return self.source
	
	def pull_output(self, pkt):
		""" Based on what verbosity level is set, parse
			the packet and return formatted data.
		"""
		data = pkt.getlayer(Raw).load
		if self.verb is 0:
			# parse the site only
			data = re.findall('Host: (.*)', data)
			if len(data) > 0: data = data[0]
			else: data = None
		elif self.verb is 1:
			data = data.split('\n')
			if len(data) > 0: data = data[0]
			else: data = None
		elif self.verb is 2:
			pass
		elif self.verb is 3:
			data = self.regex.search(data)
			if not data is None: data = data.group(0)
		return data

	def dump(self, pkt):
		""" Dump the formatted payload """
		try:
			if pkt.haslayer(Raw):
				data = self.pull_output(pkt)
				if not data is None:
					self.log_msg(data)
		except Exception, e:
			util.Error('%s'%(e))	
			return
