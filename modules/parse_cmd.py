import sys, os
sys.path[:0] = [str(os.getcwd()) + '/modules/poison/', str(os.getcwd()) + '/modules/scanner/',
		        str(os.getcwd()) + '/modules/services/']
import argparse
from net_map import NetMap
from nbns import NBNSSpoof
from ftp import FTPService
from http import HTTPService
from ssh import SSHService
from smb import SMBService
import service_scan, ap_scan,util
from scapy.all import *

#
# Provides an interface for parsing cli options.  Only certain modules are supported here (for now).
#
def parse(sysv):
	# parse debug first so the header isn't dumped twice 
	if 'debug' in sysv[1]:
		util.isDebug = True
		return

	parser = argparse.ArgumentParser(description=util.header()) 

	# other options
	parser.add_argument('-q', help='Quick network sniff with filter', action='store', dest='filter')
	parser.add_argument('--debug', help='Launch Zarp with error logging',action='store_true',default=False,dest='debug')
	parser.add_argument('--update', help='Update Zarp',action='store_true', default=False,dest='update')

	# scanners
	scan_group = parser.add_argument_group("Scanners")
	scan_group.add_argument('-s', help='Quick network map', action='store', dest='scan')
	scan_group.add_argument('--finger', help='Fingerprint scan packets', action='store_true', default=False,dest='finger')
	scan_group.add_argument('-a', help='Service scan', action='store_true', default=False, dest='service')
	scan_group.add_argument('-w', help='Wireless AP scan', action='store_true', default=False,dest='wifind')
	scan_group.add_argument('--channel',help='Set channel to scan on',action='store', dest='channel')

	# spoof
	spoof_group = parser.add_argument_group("Services")
	spoof_group.add_argument('--ssh',help='SSH server', action='store_true',default=False,dest='ssh')
	spoof_group.add_argument('--ftp',help='FTP server', action='store_true',default=False,dest='ftp')
	spoof_group.add_argument('--http',help='HTTP server', action='store_true',default=False,dest='http')
	spoof_group.add_argument('--smb', help='SMB listener',action='store_true',default=False,dest='smb')

	options = parser.parse_args()

	# initiate 
	if options.scan is not None:
		tmp = NetMap()
		tmp.net_mask = options.scan
		tmp.fingerprint = options.finger
		tmp.scan_block()
	elif options.service:
		service_scan.initialize()
	elif options.filter is not None:
		util.Msg("Sniffing with filter [%s]...(ctrl^c to exit)"%options.filter)
		try:
			sniff(filter=options.filter,store=0, prn=lambda x: x.summary())
		except KeyboardInterrupt,Exception:
			util.Msg("Exiting sniffer..")
	elif options.wifind: 
		util.debug("beginning wireless AP scan..")
		ap_scan.initialize()
	elif options.ssh:
		util.Msg('Starting SSH server...')
		tmp = SSHService()
		tmp.dump = True
		tmp.initialize()
	elif options.ftp:
		util.Msg('Starting FTP server...')
		tmp = FTPService()
		tmp.dump = True
		tmp.initialize()
	elif options.http:
		util.Msg('Starting HTTP server...')
		tmp = HTTPService()
		tmp.dump = True
		tmp.initialize()
		tmp.view()
	elif options.smb:
		util.Msg('Starting SMB listener...')
		tmp = SMBService()
		tmp.dump = True
		tmp.initialize()
	elif options.update:
		update()
	sys.exit(1)

#
# Run update routine
#
def update():
	if not util.does_file_exist('./.git/config'):
		util.Error('Not a git repo; please checkout from Github with \n\tgit clone http://github.com/hatRiot/zarp.git\n to update.')
	else:
		util.Msg('Updating Zarp...')
		ret = util.init_app('git pull git://github.com/hatRiot/zarp.git HEAD', True)
		if 'Already up-to-date' in ret:
			util.Msg('Zarp already up to date.')
		else:
			from util import version
			util.Msg('Zarp updated to version %s'%(version()))
