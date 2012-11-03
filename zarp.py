#! /usr/local/bin/python
import os, sys
sys.path.insert(0, os.getcwd() + '/modules/')
from util import print_menu, header, Error, Msg, debug
import stream, session_manager, parse_cmd
from commands import getoutput

#
# Network Attack Tool; view README for more information.
# 	[ZARP]
#	v0.01
#

def main():
	# handle command line options first
	if len(sys.argv) > 1:
		parse_cmd.parse(sys.argv)

	# menus
	main_menu =    [ 'Poisoners', 'DoS Attacks', 'Sniffers', 'Scanners',
				     'Parameter','Spoofer','Sessions']
	poison_menu =  [ 'ARP Poison', 'DNS Poison', 'DHCP Poison', 'NBNS Spoof']
	dos_menu =     [ 'NDP', 'Nestea', 'LAND', 'TCP SYN', 'SMB2',
					'DHCP Starve'
				   ]
	sniffer_menu = [ 'HTTP Sniffer', 'Password Sniffer']
	spoofer_menu = [ 'HTTP Server', 'SSH Server', 'FTP Server' ]
	scanner_menu = [ 'NetMap', 'Service Scan', 'AP Scan']
	parameter_menu = [ 'WEP Crack', 'WPA2 Crack', 'Router Pwn' ]
	
	running = True
	choice = -1
	while running:
		header()
		choice = print_menu(main_menu)		
		if choice == 0:
			# check if they've got running sessions! 
			cnt = stream.get_session_count()
			if cnt > 0:
				Msg('You have %d sessions running.  Are you sure?'%cnt)
				choice = raw_input('> ')
				if choice == 'y':
					stream.stop_session('all', -1)
					running = False	
			else:
				debug("Exiting with session count: %d"%(cnt))
				Msg("Exiting...")
				running = False
		elif choice == 1:
			while True:
				choice = print_menu(poison_menu)
				if choice == 0:
					break
				elif choice == 1:
					stream.initialize('arp')
				elif choice == 2:
					stream.initialize('dns')
				elif choice == 3:
					stream.initialize('dhcp')
				elif choice == 4:
					stream.initialize('nbns')
				elif choice == -1:
					pass
		elif choice == 2:
			while True:
				choice = print_menu(dos_menu)
				if choice == 1:
					stream.initialize('ndp')
				elif choice == 2:
					stream.initialize('nestea')
				elif choice == 3:
					stream.initialize('land')
				elif choice == 4:
					stream.initialize('tcp_syn')
				elif choice == 5:
					stream.initialize('smb2')
				elif choice == 6:
					stream.initialize('dhcp_starv')
				elif choice == 0:
					break
				elif choice == -1:
					pass
				else:
					os.system('clear')
		elif choice == 3:
			while True:
				choice = print_menu(sniffer_menu)
				if choice == 0:
					break
				elif choice == 1:
					stream.initialize('http_sniffer')
				elif choice == 2:
					stream.initialize('password_sniffer')
				elif choice == -1:
					pass
		elif choice == 4:
			while True:
				choice = print_menu(scanner_menu)
				if choice == 0:
					break
				elif choice == 1:
					stream.initialize('net_map')
				elif choice == 2:
					stream.initialize('service_scan')
				elif choice == 3:
					stream.initialize('ap_scan')
				elif choice == -1:
					pass
		elif choice == 5:
			while True:
				choice = print_menu(parameter_menu)
				if choice == 0:
					break
				elif choice == 1:
					stream.initialize('wep_crack')	
				elif choice == 2:
					Error('Not implemented.')
				elif choice == 3:
					stream.initialize('router_pwn')	
				elif choice == -1:
					pass
		elif choice == 6:
			while True:
				choice = print_menu(spoofer_menu)
				if choice == 0:
					break
				elif choice == 1:
					stream.initialize('http_server')
				elif choice == 2:
					stream.initialize('ssh_server')
				elif choice == 3:
					stream.initialize('ftp_server')
				elif choice == -1:
					pass
		elif choice == 7:
			session_manager.menu()
		elif choice == -1:
			pass

	
# Application entry
if __name__=="__main__":
	# perm check
	if int(os.getuid()) > 0:
		Error('Please run as root.')
		sys.exit(1)
	# check for forwarding
	if not getoutput('cat /proc/sys/net/ipv4/ip_forward') == '1':
		Msg('IPv4 forwarding disabled.  Enabling..')
		tmp = getoutput('sudo sh -c \'echo "1" > /proc/sys/net/ipv4/ip_forward\'')	
		if len(tmp) > 0:
			Error('Error enabling IPv4 forwarding.')
			sys.exit(1)
	# load local scapy lib
	sys.path[:0] = [str(os.getcwd()) + '/scapy'] 
	main()
