import sys, os
import util
from scanner import Scanner

#
# scan for wireless APs.  useful when searching for WEP or unprotected APs.
# This is essentially an interface to airodump-ng because its output is better
# than anything i could come up with.
#
class ap_scan(Scanner):
	def __init__(self):
		self.channel = None
		super(ap_scan,self).__init__('AP Scan')

	def initialize(self):
		try:
			if not util.check_program('airmon-ng'):
				util.Error('airomon-ng not installed.  Please install to continue.')
				return None
			util.Msg('(ctrl^c) when finished.')
			iface = util.get_monitor_adapter()
			if iface is None:
				util.Msg('No devices found in monitor mode.  Enabling...')
				iface = util.enable_monitor(self.channel)
			util.debug('Using interface %s'%iface)
			self.ap_scan(iface)
		except Exception, KeyboardInterrupt:
			return

	#
	# Sniff on the monitoring adapter 
	#
	def ap_scan(self, adapt):
		try:
			util.Msg('Scanning for access points...')
			if self.channel is None:
				os.system('airodump-ng %s'%adapt)
			else:
				os.system('airodump-ng --channel %s %s'%(self.channel, adapt))
		except Exception, j:
			util.Error('Error scanning: %s'%j)
		finally:
			util.disable_monitor()
