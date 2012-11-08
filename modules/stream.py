import os, sys, gc
sys.path[:0] = [str(os.getcwd()) + '/modules/sniffer/', str(os.getcwd()) + '/modules/dos/', 
				str(os.getcwd()) + '/modules/poison/', str(os.getcwd())+'/modules/scanner/',
				str(os.getcwd()) + '/modules/parameter/', str(os.getcwd())+'/modules/services/'] 
from util import Error, Msg, debug
from arp import ARPSpoof
from dns import DNSSpoof
from dhcp import DHCPSpoof
from nbns import NBNSSpoof
from password_sniffer import PasswordSniffer
from http_sniffer import HTTPSniffer
from net_map import NetMap
from ftp import FTPService
from http import HTTPService
import dhcp, ndp_dos, nestea_dos, land_dos, smb2_dos,dhcp_starvation,service_scan
import ap_scan, router_pwn, tcp_syn, ap_crack

#
# Main data bus for interacting with the various modules.  Dumps information, initializes objects,
# and houses all of the objects necessary to create/get/dump/stop the sniffers/poisoners.
#
# All around boss.
#

arp_sessions = {}
http_sniffers = {}
password_sniffers = {}
services = {}
global netscan,rogue_dhcp,nbnspoof	#dont manage 'many' of these; just overwrite the history of one
netscan = rogue_dhcp = nbnspoof = None

#
# Initialize a poisoner and/or DoS attack and store the object
# TODO rework this so it doesn't turn into a HUGE if/elif/elif/elif...
#
def initialize(module):
	global netscan,rogue_dhcp,nbnspoof
	debug("Received module start for: %s"%(module))
	if module == 'arp':
		tmp = ARPSpoof() 
		to_ip = tmp.initialize()
		if not to_ip is None:
			debug("Storing session for %s"%to_ip)
			arp_sessions[to_ip] = tmp
		del(tmp)
	elif module == 'dns':
		dump_module_sessions('arp')
		(module, number) = get_session_input()
		ip = get_key(module,number)
		if not ip is None:
			arp_sessions[ip].init_dns_spoof()
	elif module == 'dhcp':
		tmp = DHCPSpoof()
		if tmp.initialize():
			rogue_dhcp = tmp
	elif module == 'ndp':
		ndp_dos.initialize()	
	elif module == 'http_sniffer':
		tmp = HTTPSniffer()
		to_ip = tmp.initialize()
		if not to_ip is None:
			debug("Storing sniffer for %s"%to_ip)
			http_sniffers[to_ip] = tmp
	elif module == 'password_sniffer':
		tmp = PasswordSniffer()
		to_ip = tmp.initialize()
		if not to_ip is None:
			debug("Storing session for %s"%to_ip)
			password_sniffers[to_ip] = tmp
	elif module == 'nestea':
		nestea_dos.initialize()
	elif module == 'land':
		land_dos.initialize()
	elif module == 'smb2':
		smb2_dos.initialize()
	elif module == 'net_map':
		netscan = NetMap()
		netscan.initialize()
	elif module == 'service_scan':
		service_scan.initialize()
	elif module == 'dhcp_starv':
		dhcp_starvation.initialize()
	elif module == 'ap_scan':
		return ap_scan.initialize()	
	elif module == 'wep_crack':
		ap_crack.initialize('wep')
	elif module == 'wpa_crack':
		ap_crack.initialize('wpa')
	elif module == 'wps_crack':
		ap_crack.initialize('wps')
	elif module == 'router_pwn':
		router_pwn.initialize()
	elif module == 'tcp_syn':
		tcp_syn.initialize()
	elif module == 'nbns':
		tmp = NBNSSpoof()
		if tmp.initialize():
			nbnspoof = tmp
	elif module == 'ftp_server':
		tmp = FTPService()
		tmp.initialize_bg()
		services['ftp'] = tmp
	elif module == 'http_server':
		tmp = HTTPService()
		tmp.initialize_bg()
		services['http'] = tmp
	else:
		Error('Module \'%s\' does not exist.'%module)

#
# Dump running sessions
#
def dump_sessions():
	global arp_sessions, dns_sessions, rogue_dhcp, netscan, nbnspoof
	print '\n\t[Running sessions]'

	# dump arp poisons
	if len(arp_sessions) > 0: print '[!] ARP POISONS [arp]:'
	for (counter, session) in enumerate(arp_sessions):
		print '\t[%d] %s'%(counter, session)
		if arp_sessions[session].dns_spoof:
			print '\t|-> [!] DNS POISONS [dns]:'
			for (counter,key) in enumerate(arp_sessions[session].dns_spoofed_pair):
				print '\t|--> [%d] %s -> %s'%(counter,key.pattern,arp_sessions[session].dns_spoofed_pair[key])

	# dump http sniffers
	if len (http_sniffers) > 0: print '[!] HTTP SNIFFERS [http]:'
	for (counter, session) in enumerate(http_sniffers):
		print '\t[%d] %s'%(counter, session)
		if http_sniffers[session].log_data:
			print '\t|--> Logging to ', http_sniffers[session].log_file.name

	# dump password sniffers
	if len(password_sniffers) > 0: print '[!] PASSWORD SNIFFERS [pass]:'
	for (counter, session) in enumerate(password_sniffers):
		print '\t[%d] %s'%(counter, session)
		if password_sniffers[session].log_data:
			print '\t|--> Logging to ', password_sniffers[session].log_file.name
	
	# dump services
	if len(services) > 0: print '[!] SERVICES [serv]:'
	for (counter, session) in enumerate(services):
		print '\t[%d] %s'%(counter, session)
		if services[session].log_data:
			print '\t|--> Logging to ', services[session].log_file.name

	if not netscan is None:
		# we dont save a history of scans; just the last one
		print '\n[0] NetMap Scan [netmap]'
	if not rogue_dhcp is None:
		print '\n[1] Rogue DHCP [dhcp]'
	if not nbnspoof is None:
		print '\n[2] NBNS Spoof [nbns]'
	print '\n'

#
# Dump the sessions for a specific module
#
def dump_module_sessions(module):
	global arp_sessions, dns_sessions, dhcp_sessions, dhcp_spoof, nbnspoof
	if module == 'arp':
		print '\n\t[Running ARP sessions]'
		for (counter, session) in enumerate(arp_sessions):
			print '\t[%d] %s'%(counter, session)
	elif module == 'dns':
		print '\n\t[Running DNS sessions]'
		for (counter, session) in enumerate(arp_sessions):
			if session.dns_spoof:
				print '\t[%d] %s'%(counter, session)
	elif module == 'dhcp':
		if not rogue_dhcp is None and rogue_dhcp.running:
			print '[-] not yet'
	elif module == 'nbns':
		if not nbnspoof is None and nbnspoof.running:
		 	print '\t[2] NBNS Spoof'
#
# Return the total number of running sessions
#
def get_session_count():
	return len(arp_sessions) + len(http_sniffers)+ len(password_sniffers) + (1 if not rogue_dhcp is None else 0) + (1 if not nbnspoof is None else 0)

#
# Stop a specific session; this calls the .shutdown() method for the given object.
# All modules are required to implement this method.
# @param module is the module
# @param number is the session number (beginning with 0)
#
def stop_session(module, number):
	global rogue_dhcp, nbnspoof
	ip = get_key(module, number)
	if not ip is None:
		if module == 'arp':
			debug("Killing ARP session for %s"%ip)
			if arp_sessions[ip].shutdown():
				del(arp_sessions[ip])
		elif module == 'dns':
		  	debug("Killing DNS sessions for %s"%ip)
			arp_sessions[ip].stop_dns_spoof()
		elif module == 'ndp':
		  	Error("NDP not implemented")
		elif module == 'http':
		  	debug("Killing HTTP sniffer for %s"%ip)
			if http_sniffers[ip].shutdown():
				del(http_sniffers[ip])
		elif module == 'pass':
		  	debug("Killing password sniffer for %s"%ip)
			if password_sniffers[ip].shutdown():
				del(password_sniffers[ip])
		elif module == 'serv':
			debug('Killing service %s'%ip)
			services[ip].shutdown()
			del(services[ip])
	elif module == 'all' and number == -1:
		# this is the PANIC KILL ALL signal
		Msg('Shutting all sessions down...')
		for i in arp_sessions:
			arp_sessions[i].shutdown()
		for i in http_sniffers:
			http_sniffers[i].shutdown()
		for i in password_sniffers:
			password_sniffers[i].shutdown()

	if module == 'dhcp':
		# dhcp is a different story
		if not rogue_dhcp is None:
			rogue_dhcp.shutdown()
			rogue_dhcp = None
	elif module == 'nbns':
		if not nbnspoof is None:
			nbnspoof.shutdown()
			nbnspoof = None
	gc.collect()

#
# Some sniffers have information to dump, so for those applicable, this'll initiate it.
# Module should implement the .view() method for dumping information to.
#
def view_session(module, number):
	global netscan, nbnspoof
	ip = get_key(module, number)
	if module == 'netmap':
		netscan.view()
	elif module == 'nbns':
		nbnspoof.view()
	elif not ip is None:
		if module == 'http':
			debug("Beginning HTTP dump for %s"%ip)
			http_sniffers[ip].view()
		elif module == 'pass':
			debug("Beginning password dump for %s"%ip)
			password_sniffers[ip].view()
		elif module == 'arp' or module == 'dns':
			debug("Beginning ARP/DNS dump for %s"%ip)
			arp_sessions[ip].view()
		elif module == 'serv':
			Msg("Beginning Serv dump for %s"%ip)
			services[ip].view()
	else:
		return

#
# Start logging a session
#
def start_log_session(module, number, file_location):
	ip = get_key(module, number)
	if not ip is None:
		if module == 'http':
			debug("Beginning HTTP logger")
			http_sniffers[ip].log(True, file_location)
		elif module == 'pass':
			debug("Beginning password logger")
			password_sniffers[ip].log(True, file_location)
		elif module == 'serv':
			debug('Beginning %s logger'%ip)
			services[ip].log(True, file_location)
		else:
			Error('Module \'%s\' does not have a logger.'%module)
	else:
		Error('%s session \'%s\' could not be found.'%(module, number))
		Error('Logging canceled.')

#
# Stop logging a session 
#
def stop_log_session(module, number):
	ip = get_key(module, number)
	if not ip is None:
		if module == 'http':
			debug("Stopping HTTP logger")
			http_sniffers[ip].log(False, None)
		elif module == 'pass':
			debug("Stopping password logger")
			password_sniffers[ip].log(False, None)
		elif module == 'serv':
			debug('Stopping %s logger'%ip)
			services[ip].log(False, None)
		else:
			Error('Module \'%s\' does not have a logger.'%module)
	else:
		Error('%s session \'%s\' could not be found.'%(module, number))
		Error('Logging could not be stopped.')
#
# Internal function for grabbing IP address from a module/index
#
def get_key(module, number):
	if module == 'http':
		if len(http_sniffers) <= number:
			Error('Invalid session number (0-%d)'%len(http_sniffers))
			return None
		return http_sniffers.keys()[number]
	elif module == 'pass':
		if len(password_sniffers) <= number:
			Error('Invalid session number (0-%d)'%len(password_sniffers))
			return None
		return password_sniffers.keys()[number]
	elif module == 'arp' or module == 'dns':
		if len(arp_sessions) <= number:
			Error('Invalid session number (0-%d)'%len(arp_sessions))
			return None
		return arp_sessions.keys()[number]
	elif module == 'serv':
		if len(services) <= number:
			Error('Invalid session number (0-%d)'%len(services))
			return None
		return services.keys()[number]
	elif module == 'none' and number == -1:
		return None
	return None

#
# read in the module/number for interacting with a specific running module
#
def get_session_input():
	try:
		tmp = raw_input('[module] [number]> ')
		(module, number) = tmp.split(' ')
		if not module is None and not number is None:
			return (str(module), int(number))
	except Exception: 
		Error('Must specify [module] followed by [number]\n')
		return (None, None)

#
# view a modules information
#
def view_info (module):
	if module == 'http':
		HTTPSniffer().info()	
