from commands import getoutput
import sys, os
import util

#
# scan for wireless APs.  useful when searching for WEP or unprotected APs.
# This is essentially an interface to airodump-ng because its output is better
# than anything i could come up with.
#
def initialize():
	try:
		if not util.check_program('airmon-ng'):
			util.Error('airomon-ng not installed.  Please install to continue.')
			return False
		util.Msg('(ctrl^c) when finished.')
		iface = util.get_monitor_adapter()
		if iface is None:
			util.Msg('No devices found in monitor mode.  Enabling...')
			iface = util.enable_monitor()
		util.debug('Using interface %s'%iface)
		ap_scan(iface)
	except Exception, KeyboardInterrupt:
		return

#
# Sniff on the monitoring adapter 
#
def ap_scan(adapt):
	try:
		print '[!] Scanning for access points...'
		os.system('airodump-ng %s'%adapt)
	except Exception, j:
		util.Error('Error scanning: %s'%j)
	finally:
		util.disable_monitor()
