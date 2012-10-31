import sys, os
sys.path[:0] = [str(os.getcwd()) + '/modules/poison/', str(os.getcwd()) + '/modules/scanner/',
		        str(os.getcwd()) + '/modules/services/']
from optparse import OptionParser, OptionGroup
from net_map import NetMap
from nbns import NBNSSpoof
from ftp import FTPService
from ssh import SSHService
from http import HTTPService
import service_scan, ap_scan,util
from scapy.all import *

#
# Provides an interface for parsing cli options.  Only certain modules are supported here (for now).
#
def parse(sysv):
	parser = OptionParser()
	
	# scanners
	scan_group = OptionGroup(parser, "Scanners")
	scan_group.add_option('-s', help='Quick network map', action='store', dest='scan')
	scan_group.add_option('--finger', help='Fingerprint scan packets', action='store_true', default=False,dest='finger')
	scan_group.add_option('-a', help='Service scan', action='store_true', default=False, dest='service')
	parser.add_option('-q', help='Quick network sniff with filter', action='store', dest='filter')
	scan_group.add_option('-w', help='Wireless AP scan', action='store_true', default=False,dest='wifind')
	scan_group.add_option('--channel',help='Set channel to scan on',action='store', dest='channel')
	parser.add_option('--debug', help='Launch Zarp with error logging',action='store_true',default=False,dest='debug')

	# spoof
	spoof_group = OptionGroup(parser, "Spoofers")
	spoof_group.add_option('--nbns', help='NBNS Spoofing', action='store_true',default=False,dest='nbns')
	spoof_group.add_option('--ssh',help='SSH server', action='store_true',default=False,dest='ssh')
	spoof_group.add_option('--ftp',help='FTP server', action='store_true',default=False,dest='ftp')
	spoof_group.add_option('--http',help='HTTP server', action='store_true',default=False,dest='http')

	parser.add_option_group(scan_group)
	parser.add_option_group(spoof_group)	
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
		util.debug("Performing basic sniffer with filter [%s]"%options.filter)
		try:
			sniff(filter=options.filter,store=0, prn=lambda x: x.summary())
		except KeyboardInterrupt,Exception:
			util.Msg("Exiting sniffer..")
	elif options.wifind: 
		util.debug("beginning wireless AP scan..")
		ap_scan.initialize()
	elif options.nbns:
		tmp = NBNSSpoof()
		tmp.initialize()	
	elif options.ssh:
		tmp = SSHService()
		tmp.initialize()
	elif options.ftp:
		util.Msg('Starting FTP server...')
		tmp = FTPService()
		tmp.initialize()
	elif options.http:
		util.Msg('Starting HTTP server...')
		tmp = HTTPService()
		tmp.dump = True
		tmp.initialize()
		tmp.view()
	sys.exit(1)
