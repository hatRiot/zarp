import util
import abc

#
# Abstract Sniffer
#

class Sniffer(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self, module):
		self.which_sniffer = module # sniffer title 
		self.source = None          # source to sniff from
		self.sniff = False          # sniffing is on/off
		self.dump_data = False      # dump output to screen
		self.log_data = False       # logging on/off
		self.log_file = None        # logging file

	@abc.abstractmethod
	def dump(self, pkt):
		pass

	@abc.abstractmethod
	def traffic_sniffer(self):
		pass

	@abc.abstractmethod
	def initialize(self):
		pass
	
	#
	# Initiate a sniffer shutdown
	#
	def stop_callback(self):
		if self.sniff:
			return False
		util.debug('%s sniffer shutdown...'%self.which_sniffer)
		return True

	#
	# Flip the off switch
	#
	def shutdown(self):
		if self.sniff:
			self.sniff = False
		if self.log_data:
			self.log(False, None)
		util.debug('%s sniffer shutting down'%self.which_sniffer)
		return True

	#
	# Dump output to the user
	#
	def view(self):
		try:
			util.Msg('Dumping %s from %s...'%(self.which_sniffer, self.source))
			while True:
				self.dump_data = True
		except KeyboardInterrupt:
			self.dump_data = False
			return

	#
	# Log sniffer output
	#
	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				util.debug('Starting %s logger...'%self.which_sniffer)
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
				util.debug('%s logger shutdown completed.'%self.which_sniffer)
			except Exception, j:
				util.Error('Error closing logger: %s'%j)
				self.log_data = False
				return
