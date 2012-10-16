import stream 
from util import Error
from threading import Thread
from scapy.all import *

#
# Module sniffs incoming traffic for any HTTP traffic and dumps it.
#
class HTTPSniffer:
	def __init__(self):
		self.source = ''
		self.sniff = False
		self.dump_data = False
		self.log_data = False
		self.log_file = None

	#
	# Sniffs for HTTP traffic by checking the destination port (for now)
	# TODO: https
	#
	def traffic_sniffer(self):
		sniff(filter="tcp and dst port 80 and src %s"%self.source, store=0, prn=self.dump, stopper=self.stop_callback,
						stopperTimeout=3)
	#
	# initialize the sniffer by getting the source address from the user
	#
	def initialize(self):
		self.source = raw_input('[!] Enter address to listen for HTTP packets from: ')
		tmp = raw_input('[!] Sniff HTTP traffic from %s.  Is this correct? '%self.source)
		if tmp == "n":
			return None
		self.sniff = True
		sniff_thread = Thread(target=self.traffic_sniffer)
		sniff_thread.start()
		return self.source

	#
	# callback for shutting down the sniffer
	#
	def stop_callback(self):
		if self.sniff:
			return False
		print '[dbg] http sniffer shutdown'
		return True
	#
	# dump the HTTP payload to the screen IF they're viewing the session
	#
	def dump(self, pkt):
		try:
			if pkt.haslayer(Raw) and self.dump_data:
				print pkt.getlayer(Raw).load
			if self.log_data and pkt.haslayer(Raw):
				self.log_file.write(str(pkt.getlayer(Raw).load))	
		except KeyboardInterrupt:
			self.dump_data = False
			return

	#
	# sit in the loop and dump plaintext HTTP payloads to the screen, catching when they control+c
	#
	def view(self):
		try:
			while True:
				self.dump_data = True
		except KeyboardInterrupt:
			self.dump_data = False
			return
	
	#
	# Set if we want to log data to a file or not
	#
	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				print '[dbg] starting logger...'
				self.log_file = open(log_loc, 'w+')
			except Exception, j:
				Error('Error opening log file: %s'%j)
				self.log_file = None
				return
			self.log_data = True
		elif not opt and self.log_data:
			try:
				self.log_file.close()
				self.log_file = None
				self.log_data = False
				print '[dbg] logger shutdown completed.'
			except Exception, j:
				print '[dbg] Error closing logger: ', j
			
	#
	# Shutdown the sniffer; there's not much to do but close the sniffing thread and any
	# logging stuff.
	#
	def shutdown(self):
		if self.sniff:
			self.sniff = False
		# if logging, gracefully close file handles
		if self.log_data:
			self.log(False, None)
		print '[dbg] http sniffer shutting down'
		return True
