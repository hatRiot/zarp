import time, socket
import util
from ftplib import FTP
from commands import getoutput
from scapy.all import *

#
# Implementation of a service scanner; more focused than the network scanner.
# Remember that this is an intranet tool; a scan of google.com won't turn anything up.
#

services = {
		     'ftp': 21,
		     'ssh': 22,
		  'telnet':23,
			'smtp': 25,
			 'dns': 53,
			'dhcp': 67,
			'http': 80,
			'pop3': 110,
			'snmp': 161,
			 'smb': 445,
		   'mysql': 3306,
		   'mssql': 1433,
		'postgres': 5432
		    }

def initialize():
	block = raw_input('[!] Enter net mask: ')
	service = raw_input('[!] Enter service or port to scan for: ')
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
	tmp = []
	if service.isdigit():
		tmp.append(int(service))
	elif ',' in service:
		service = service.split(',')
		# list of ports
		if service[0].isdigit():
			service = map(int, service)
		# list of services
		else:
			tmp = []
			for i in service: 
				try:
					tmp.append(services[i])
				except:
					util.Error('\'%s\' is not a supported service.'%i)
					continue
	elif service in services:
		tmp.append(services[service])
	else:
		util.Error('Service \'%s\' not recognized.'%(service))
		return
	service = tmp
	
	# parsing is done, we've got a list of integers. SYN the port and pass
	# processing off if we need to do service specific querying
	try:
		(ans, unans) = arping(block)
		if 67 in service:
			dhcp_scan()
		for s,r in ans:
			ip = r[ARP].getfieldval('psrc')
			print '\t[+] %s'%(ip)
			for port in service:
				if port is 67: 
					continue
				elif port is 161:
					snmp_query(ip)
					continue
				elif port is 53:
					zone_transfer(ip)
					continue
				pkt = sr1(IP(dst=ip)/TCP(flags='S',dport=port),timeout=1)
				if not pkt is None and pkt[TCP].getfieldval('flags') == 18L:
					print '\t  %d \t %s'%(pkt[TCP].sport, 'open')
					if port is services['ftp']:
						ftp_info(ip)
					elif port is services['ssh']:
						# todo: change this up so if ssh is on another port...
						ssh_info(ip,port)
					elif port is services['smb']: 
						smb_info(ip)
				sr(IP(dst=ip)/TCP(flags='FA',dport=port),timeout=1)
	except Exception, j:
		util.debug("error: %s"%j)	
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
		util.Msg('No DHCP servers found.')
	
#
# query and dump snmp info
# TODO: walk through different versions and try different passwords
#
def snmp_query(ip):
	pkt = IP(dst=ip)/UDP(sport=161)
	pkt /= SNMP(community='public', PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))]))
	recv = sr1(pkt)
	print '\t[+] SNMP Dump\n ', recv[SNMP].show()

#
# DNS zone transfer 
# TODO: better way than interfacing with dig?
#
def zone_transfer(addr):
	record = util.init_app("dig %s axfr"%addr, True)
	if 'failed: connection refused.' in record:
		util.Error('Host disallowed zone transfer')
		return
	print record

#
# ssh banner grab
#
def ssh_info(ip, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		sock.connect((ip,port))
		data = sock.recv(1024)
		print '\t  |- ',data
		sock.close()
	except Exception, j:
		util.debug('Error in SSH grab: %s'%j)
		sock.close()
	return	

#
# banner grab the FTP, check if we can log in anonymously
#
def ftp_info(ip):
	con = FTP(ip)
	banner = con.getwelcome()
	# dump banner
	for line in banner.split('\n'):
		print '\t  |-' + line
	
	print '\t  [+] Checking anonymous access...'
	try:
		con.login()
	except:
		print '\t  [-] No anonymous access.'
		con.close()
		return
	
	# get the logged in dir
	data = con.pwd()
	if data is not None:
		print '\t  [+] Anonymous access available.'
		print '\t  [+] Directory: ', data 
	con.close()

#
# dump smb shares.  interfaces with SMBclient
#
def smb_info(ip):
	if not util.check_program('smbclient'):
		print '\t  [-] Skipping SMB enumeration.'
		return
	tmp = 'smbclient -U GUEST -N --socket-options=\'TCP_NODELAY IPTOS_LOWDELAY\' -L %s'%(ip)
	data = util.init_app(tmp, True)
	
	# dump smb reponse
	for line in data.split('\n'):
		print '\t  |-', line
