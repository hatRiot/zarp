from sniffer import Sniffer
from scapy.all import *
from threading import Thread
import socket
import util
import re
import asyncore

try: import nfqueue 
except: 
	util.Error('nfqueue libs not found.') 

""" This module emulates the find & replace utility
	from ettercrap.  Given a string to match and a replacement,
	this will parse packets and attempt to modify its payload.
	As of writing, this will only attempt to parse and replace
	inside payloads; if you modify an HTTP header to GET a
	different site, the IP will not be altered.  TODO.

	Requirements are nfqueue-bindings-python from wzdftpd.net and
	libnetfilter-queue.
"""

class packet_modifier(Sniffer):
	def __init__(self):
		self.input_ipt_rule  = "iptables -I INPUT -p tcp -j NFQUEUE --queue-num 0"
		self.output_ipt_rule = "iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num 0" 
		self.match           = ""
		self.replace         = ""
		self.async_queue     = None
		super(packet_modifier,self).__init__("Packet Modifier")

	def initialize(self):
		"""Initialize the replacer module"""
		util.Msg('Note: This module currently only supports payload modifications.')
		while True:
			try:
				self.match = raw_input('[!] Match: ')
				self.replace = raw_input('[!] Replace with: ')
				tmp = raw_input('[!] Match %s and replace with %s.  Is this correct?[y] '%
																(self.match,self.replace))
				if 'n' in tmp.lower():
					return
				break
			except KeyboardInterrupt: return
			except:
				util.Error('Invalid input')
				continue

		# set iptable rules
		self.manage_iptable()
		
		thread = Thread(target=self.injector)
		thread.start()

		# return our display for session management
		return '%s -> %s'%(self.match, self.replace)

	def manage_iptable(self,enable=True):
		"""Add/remove the iptable rules.  Enable
		   to enable, else remove.
		"""
		if enable:
			util.init_app(self.input_ipt_rule)	
			util.init_app(self.output_ipt_rule)
		else:
			util.init_app(self.input_ipt_rule.replace('-I','-D'))
			util.init_app(self.output_ipt_rule.replace('-I','-D'))

	def injector(self):
		""" Launch the asynch loop to process events.
		"""
		try:
			self.async_queue = async_nfqueue(self.handler)
			asyncore.loop()	
		except: pass 
		
	def handler(self, dumb, payload):
		"""Callback for receiving and modifying packets"""
		# parse into scapy packet
		pkt = IP(payload.get_data())
		if pkt.haslayer(Raw) and TCP in pkt and self.match in pkt[TCP].load:
			data = str(pkt.getlayer(Raw).load)
			mod_pkt = copy.copy(pkt) # make a copy of packet for mods
			data = re.sub(self.match, self.replace, data)
			# recalculate IP length and checksums
			del mod_pkt[IP].chksum
			del mod_pkt[TCP].chksum
			mod_pkt[IP].len = (mod_pkt[IP].len - len(pkt[TCP].load)) + len(data)
			mod_pkt[TCP].load = data
			payload.set_verdict_modified(nfqueue.NF_REPEAT,str(mod_pkt),len(mod_pkt))
			return 0

		payload.set_verdict(nfqueue.NF_ACCEPT)
		return 0

	def dump(self, pkt): 
		""" we don't use this """
		pass

	def session_view(self):
		"""Session management viewer"""
		return "%s -> %s"%(self.match, self.replace)

	def shutdown(self):
		"""Shut the sniffer down and wipe the iptable rules"""
		try:
			self.async_queue.handle_close()
		except: pass
		self.manage_iptable(False)
		return True

class async_nfqueue(asyncore.file_dispatcher):
	"""Asynchronously dispatch events.  Taken from
	   nfq_asyncore.py
	"""
	def __init__(self, callback, nqueue=0, family=socket.AF_INET, maxlen=5000, map=None):
		self.queue = nfqueue.queue()
		self.queue.set_callback(callback)
		self.queue.fast_open(nqueue, family)
		self.queue.set_queue_maxlen(maxlen)
		self.fd = self.queue.get_fd()
		asyncore.file_dispatcher.__init__(self,self.fd,map)
		self.queue.set_mode(nfqueue.NFQNL_COPY_PACKET)
	
	def handle_close(self):
		self.close()

	def handle_read(self):
		"""Process up to 10 events; needs some performance
		   tuning as I'm not sure where the sweet spot is.
		"""
		self.queue.process_pending(10)

	def writable(self):
		return False
