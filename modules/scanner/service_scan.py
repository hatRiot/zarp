import time
from scapy.all import *

#
# Implementation of a service scanner; more focused than the network scanner.
# Remember that this is an intranet tool; a scan of google.com won't turn anything up.
#

services = {
		    'ftp' : 21,
		    'ssh' : 22,
			'telnet':23,
			'smtp' : 24,
			'dns' : 53,
			'http' : 80,
			'snmp' : 161
		    }

def initialize():
	block = raw_input('[!] Enter net mask: ')
	service = raw_input('[!] Enter service to scan for: ')
	tmp = raw_input('[!] Scan %s for %s.  Is this correct? '%(block, service))
	if tmp == 'n':
		return

	print '[!] Beginning service scan...'
	service_scan(block,service)

#
# parse up their list of things.  it can be a single port, a list of ports, a supported service, 
# or a list of services.  if there's ever a need for a 'find all ports on this box', i'll include it.
# For now the point of this module is to be more focused on what you're looking for, and thus has a 
# very simple port scanner.
#
def service_scan ( block, service ):
	conf.verb = 0
	if service.isdigit():
		service = int(service)
	elif ',' in service:
		service = service.split(',')
		# list of ports
		if service[0].isdigit():
			service = map(int, service)
		# list of services
		else:
			try:
				tmp = []
				for i in service: 
					tmp.append(services[i])
				service = tmp
			except:
				print '[-] \'%s\' is not a supported service.'%i
				return
	elif service in services:
		service = services[service]	
	else:
		print '[-] Service \'%s\' not recognized.'%(service)
		return
	
	# parsing is done, we've got a list of integers. SYN the port.
	try:
		(ans, unans) = arping(block)
		for s,r in ans:
			ip = r[ARP].getfieldval('psrc')
			if type(service) is list:
				for port in service:
					pkt = sr1(IP(dst=ip)/TCP(flags='S',dport=port),timeout=1)
					if not pkt is None and pkt[TCP].getfieldval('flags') == 18L:
						print '\t[+] %s'%(ip)
						print '\t  %d \t %s'%(pkt[TCP].sport, 'open')
			else:
				pkt = sr1(IP(dst=ip)/TCP(flags='S',dport=service),timeout=1)
				if not pkt is None and pkt[TCP].getfieldval('flags') == 18L:
					print '\t[+] %s'%(ip)
					print '\t  %d \t %s'%(pkt[TCP].sport, 'open')
					sr(IP(dst=ip)/TCP(flags='FA',dport=service),timeout=1)
	except Exception, j:
		print '[dbg] error: ', j
	print '\n'
