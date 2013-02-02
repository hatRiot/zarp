import util, config
import abc
from scapy.all import sniff
from threading import Thread

#
# Abstract Sniffer
#

class Sniffer(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self, module):
		self.which = module		              # sniffer title 
		self.source = config.get('ip_addr')   # source to sniff from
		self.sniff = False          		  # sniffing is on/off
		self.dump_data = False      		  # dump output to screen
		self.sniff_filter = None		      # filter for the traffic sniffer
		self.log_data = False       		  # logging on/off
		self.log_file = None        		  # logging file
		self.sniff_thread = None			  # Traffic sniffing thread
		# initialize thread
		self.sniff_thread = Thread(target=self.traffic_sniffer)
		# retrieve the source IP
		self.get_ip()


	@abc.abstractmethod
	def dump(self, pkt):
		pass


	@abc.abstractmethod
	def initialize(self):
		pass

	#
	# Log the message
	#
	def log_msg(self, msg):
		if self.dump_data:
			util.Msg(msg)
		if self.log_data:
			self.log_writer(msg)

	#
	# Session viewer
	#
	def session_view(self):
		return '%s'%self.source

	#
	# Sniff traffic with the appropriate 
	#
	def traffic_sniffer(self):
		if self.sniff_filter is None:
			raise NotImplementedError, "sniff_filter not initialized!"

		sniff(filter=self.sniff_filter,store=0,prn=self.dump,stopper=self.stop_callback,
						stopperTimeout=3)

	#
	# Retrieve the IP address to listen on; default to default adapter IP
	#
	def get_ip(self):
		try:
			tmp = raw_input('[!] Enter address to listen on [%s]: '%self.source)
		except KeyboardInterrupt:
			return
		except:
			return 
			
		if tmp.strip() != '':
			self.source = tmp
		return

	#
	# Initiate a sniffer shutdown
	#
	def stop_callback(self):
		if self.sniff:
			return False
		util.debug('%s sniffer shuting down...'%self.which)
		return True

	#
	# Flip the off switch
	#
	def shutdown(self):
		if self.sniff:
			self.sniff = False
		if self.log_data:
			self.log(False, None)
		util.debug('%s sniffer shutdown'%self.which)
		return True

	#
	# Dump output to the user
	#
	def view(self):
		try:
			util.Msg('Dumping %s from %s...'%(self.which, self.source))
			while True:
				self.dump_data = True
		except KeyboardInterrupt:
			self.dump_data = False
			return

	#
	# Write to the log; handle issues and auto flush.
	# Default buffers may be used if performance proves to be an
	# issue.
	#
	def log_writer(self, msg):
		if self.log_data:
			self.log_file.write(msg)
			self.log_file.flush()

	#
	# Log sniffer output
	#
	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				util.debug('Starting %s logger...'%self.which)
				self.log_file = open(log_loc, 'w+')
			except Exception, j:
				util.Error('Error opening \'%s\' log file: %s'%(log_loc, j))
				self.log_file = None
				return
			self.log_data = True
		elif not opt and self.log_data:
			try:
				self.log_file.close()
				self.log_file = None
				self.log_data = False
				util.debug('%s logger shutdown completed.'%self.which)
			except Exception, j:
				util.Error('Error closing logger: %s'%j)
				self.log_data = False
				return
