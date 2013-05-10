import sys, os
sys.path[:0] = [str(os.getcwd()) + '/src/modules/poison/', str(os.getcwd()) + '/src/modules/scanner/',
		        str(os.getcwd()) + '/src/modules/services/']
import argparse
from net_map import net_map
from nbns import nbns
from ftp import ftp
from http import http 
from ssh import ssh 
from smb import smb 
from access_point import access_point
from ap_scan import ap_scan
from service_scan import service_scan
import util, config

from scapy.all import *
from scapy.error import Scapy_Exception

def parse(sysv):
	""" Provides an interface for parsing CLI options.
		As of now (v.10) this is set manually; eventually
		it will be refactored to allow modules to set their
		own CLI interfaces.
	"""
	parser = argparse.ArgumentParser(description=util.header()) 

	# other options
	parser.add_argument('-q', help='Quick network sniff with filter', action='store', dest='filter')
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
	spoof_group.add_argument('--wap', help='Wireless Access Point', action='store_true',default=False,dest='wap')

	options = parser.parse_args()

	# initiate 
	if options.scan is not None:
		tmp = net_map()
		tmp.net_mask = options.scan
		tmp.fingerprint = options.finger
		tmp.scan_block()
	elif options.service:
		tmp = service_scan()
		tmp.initialize()
	elif options.filter is not None:
		util.Msg("Sniffing with filter [%s]...(ctrl^c to exit)"%options.filter)
		try:
			sniff(filter=options.filter,store=0, prn=lambda x: x.summary())
		except KeyboardInterrupt,Exception:
			util.Msg("Exiting sniffer..")
		except Scapy_Exception as msg:
			util.Error(msg)
			sys.exit(1)
	elif options.wifind: 
		util.debug("beginning wireless AP scan..")
		scan = ap_scan()
		if options.channel: scan.channel = options.channel
		scan.initialize()
	elif options.ssh:
		util.Msg('Starting SSH server...')
		tmp = ssh()
		tmp.initialize()
		tmp.dump = True
	elif options.ftp:
		util.Msg('Starting FTP server...')
		tmp = ftp() 
		tmp.initialize()
		tmp.dump = True
	elif options.http:
		util.Msg('Starting HTTP server...')
		tmp = http()
		tmp.initialize()
		tmp.dump = True
	elif options.smb:
		util.Msg('Starting SMB listener...')
		tmp = smb()
		tmp.initialize()
		tmp.dump = True
	elif options.wap:
		util.Msg('Starting wireless access point...')
		tmp = access_point()
		tmp.initialize()
	elif options.update:
		update()
	sys.exit(1)

def update():
	"""Run update routine
	"""
	if not util.does_file_exist('./.git/config'):
		util.Error('Not a git repo; please checkout from Github with \n\tgit clone http://github.com/hatRiot/zarp.git\n to update.')
	else:
		util.Msg('Updating Zarp...')
		ret = util.init_app('git branch -a | grep \'* dev\'', True)
		if len(ret) > 3:
			util.Error('You appear to be on the dev branch.  Please switch off dev to update.')
			return

		ret = util.init_app('git pull git://github.com/hatRiot/zarp.git HEAD', True)
		if 'Already up-to-date' in ret:
			util.Msg('Zarp already up to date.')
		elif 'fatal' in ret:
			util.Error('Error updating Zarp: %s'%ret)
		else:
			from util import version
			util.Msg('Zarp updated to version %s'%(version()))
