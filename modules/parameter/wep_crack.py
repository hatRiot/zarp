from scapy.all import *

#
# Crack a WEP AP
#
class WEPCrack:
	def __init__(self):
		self.ap_addr = None

	#
	#
	#
	def initialize(self):
		try:
			self.ap_addr = raw_input('[!] AP address: ')
			tmp = raw_input('[!] Attempt to crack %s WEP key? '%self.ap_addr)
			if 'n' in tmp.lower():
				return
			print '[!] Beginning WEP crack...'
			self.crack()
		except Exception, j:
			print '[dbg] ', j
			return

	#
	#
	#
	def crack(self):
		print '[dbg] todo lol'
#	sniff()
