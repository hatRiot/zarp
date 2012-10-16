import sys, os
sys.path.insert(0, os.getcwd() + '/modules/scanner/')
from optparse import OptionParser
from net_map import NetMap
import service_scan, ap_scan,util
from scapy.all import *

#
# Provides an interface for parsing cli options.  Only certain modules are supported here (for now).
#
def parse(sysv):
	parser = OptionParser()
	parser.add_option('-s', help='Quick network map', action='store', dest='scan')
	parser.add_option('--finger', help='Fingerprint scan packets', action='store_true', default=False,dest='finger')
	parser.add_option('-a', help='Service scan', action='store_true', default=False, dest='service')
	parser.add_option('-q', help='Quick network sniff with filter', action='store', dest='filter')
	parser.add_option('-w', help='Wireless AP scan', action='store_true', default=False,dest='wifind')
	parser.add_option('--channel',help='Set channel to scan on',action='store', dest='channel')
	parser.add_option('--debug', help='Launch Zarp with error logging',action='store_true',default=False,dest='debug')

	(options, args) = parser.parse_args(sysv)
	
	# debug check; for right now must be run in interactive mode
	if options.debug:
		util.isDebug = True
		return

	# initiate the netmap module
	if options.scan is not None:
		tmp = NetMap()
		tmp.net_mask = options.scan
		tmp.fingerprint = options.finger
		tmp.scan_block()
	elif options.service:
		service_scan.initialize()
	elif options.filter is not None:
		print '[dbg] performing basic sniffer with filter [%s]'%options.filter
		try:
			sniff(filter=options.filter,store=0, prn=lambda x: x.summary())
		except KeyboardInterrupt,Exception:
			print '[!] Exiting sniffer..'
	elif options.wifind: 
		print '[dbg] beginning wireless AP scan..'
		ap_scan.initialize()
	sys.exit(1)
