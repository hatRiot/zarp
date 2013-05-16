import stream
import util
import re
from collections import namedtuple
from config import pptable
from sniffer import Sniffer
from scapy.all import *

class http_sniffer(Sniffer):
	"""HTTP sniffer that allows various verbosity levels
	"""
	def __init__(self):
		self.verbs    = [ 'Site Only', 'Request String', 'Request and Payload',
					      'Session IDs', 'Custom Regex' ]
		self.verb     = 0
		self.sessions = {}
		self.regex    = None
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

				if self.verb is 4:
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
	
	def manage_sessions(self, data):
		""" Parse and manage session IDs.
			Return this requests ID
		"""
		# is there a session ID here?
		if 'session' in data.lower():

			# grab the host
			host = re.findall('Host: (.*)', data)
			if len(host) > 0: host = host[0]
			else: return None

			# grab the session; there are different ways this can be formatted in 
			# the payload.  this should, for the most part, get the popular ones.  
			# Probably will have a bunch of false positives, so this'll be tweaked.
			session_id = re.findall('.*?sess.*?[:|=](..*?)(&|;|$|:|\n| )', data.lower())
			if len(session_id) > 0: session_id = session_id[0][0]
			else: return None 

			self.sessions[host] = session_id
			return session_id
		
		
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
			data = self.manage_sessions(data)
		elif self.verb is 4:
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

	def view(self):
		""" Overload view so we can print out
			sessions in a pretty table.
		"""
		if self.verb is 3:
			Setting = namedtuple('Setting', ['Host', 'SessionID']) 
			table = []
			for i in self.sessions.keys():
				data = Setting(str(i).strip(), str(self.sessions[i]).strip())
				table.append(data)
			pptable(table)
		else:
			super(http_sniffer,self).view()

	def session_view(self):
		""" Overloaded to return both the sniffed 
			address and the verbosity.
		"""
		return '%s [%s]'%(self.source, self.verbs[self.verb])
