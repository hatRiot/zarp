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
			'dhcp' : 67,
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
					if port == 67:
						dhcp_scan()
						continue
					pkt = sr1(IP(dst=ip)/TCP(flags='S',dport=port),timeout=1)
					if not pkt is None and pkt[TCP].getfieldval('flags') == 18L:
						print '\t[+] %s'%(ip)
						print '\t  %d \t %s'%(pkt[TCP].sport, 'open')
			else:
				if service == 67:
					dhcp_scan()
					return 
				pkt = sr1(IP(dst=ip)/TCP(flags='S',dport=service),timeout=1)
				if not pkt is None and pkt[TCP].getfieldval('flags') == 18L:
					print '\t[+] %s'%(ip)
					print '\t  %d \t %s'%(pkt[TCP].sport, 'open')
					sr(IP(dst=ip)/TCP(flags='FA',dport=service),timeout=1)
	except Exception, j:
		print '[dbg] error: ', j
	print '\n'

#
# Scan for DHCP servers
#
def dhcp_scan():
	conf.checkIPaddr = False
	fm, hw_addr = get_if_raw_hwaddr(conf.iface)
	dhcp_discovery = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw_addr)/DHCP(options=[("message-type","discover"),"end"])
	answered,unanswered = srp(dhcp_discovery, multi=True, timeout=10)
	
	# check/parse responses
	if len(answered) > 0:
		print '[+] Responding DHCP servers'
		print '\t   {0:21} {1:25}'.format('[IP]', '[MAC]')
		for i, f in answered:
			print '\t{0:20} {1:20}'.format(f[IP].src, f[Ether].src)
		print '\n'
	else:
		print '[-] No DHCP servers found.'
