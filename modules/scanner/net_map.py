import socket, time
from util import Error
from scapy.all import *

#
# Map the local network by gathering active hosts within the given range
#
class NetMap:
	def __init__(self):
		self.net_mask = ''
		self.available_hosts = {}
		self.fingerprint = False
		self.rev_lookup = False

	def initialize(self):
		try:
			self.net_mask = raw_input('[!] Enter netmask: ')
			self.fingerprint = True if (raw_input('[!] Fingerprint? ')=='y') else False
		except Exception:
			return
		self.scan_block()

	#
	# ARPing the local network for all hosts (ip/mac)
	# TODO Complete fingerprinting
	#
	def scan_block(self):
		conf.verb = 0
		print '[!] Beginning host scan with netmask %s...'%(self.net_mask)
		try:
			start = time.clock()	
			(ans, unans) = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.net_mask),timeout=1, inter=0.1)
			elapsed = (time.clock() - start)
			print '[!] Scan of %s completed in %s seconds with %d hosts responding.'%(self.net_mask,elapsed,len(ans))
			for s,r in ans:
			 	ip = r[ARP].getfieldval('psrc')
			 	mac = r[ARP].getfieldval('hwsrc')
			 	if self.fingerprint:
				 	host = ''
				 	try:
						if hasattr(socket, 'setdefaulttimeout'):
							socket.setdefaulttimeout(3)
						host = socket.gethostbyaddr(ip)[0]
					except:
						host = ''
					print "\t%s : %s (%s)"%(mac,ip,host)
				else:
					print '\t%s : %s'%(mac,ip)
				self.available_hosts[mac] = ip
		except Exception, j:
		  	print '[dbg] error: ', j
			Error('Error with net mask.  Cannot scan given block.')
			return
		print '\n'

	#
	# Dump all the available hosts found
	#
	def view(self):
		print '\n\t[!] Available hosts in range %s:'%self.net_mask
		for mac in self.available_hosts.keys():
			print '\t%s : %s'%(mac,self.available_hosts[mac])
