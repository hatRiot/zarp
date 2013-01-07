import util
import abc

#
# Abstract service
#

class Service(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self, service):
		self.which_service = service
		self.running = False
		self.log_data = False
		self.log_file = None
		self.dump = False

	@abc.abstractmethod
	def initialize(self):
		pass

	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				util.debug('Starting %s logger...')
				self.log_file = open(log_loc, 'w+')
			except Exception, j:
				util.Error('Error opening log file for %s: %s'%
								(self.which_service, j))
				self.log_file = None
			self.log_data = True
		elif not opt and self.log_data:
			try:
				self.log_file.close()
				self.log_file = None
				self.log_data = False
				util.debug('%s shutdown complete.'%self.which_service)
			except Exception, j:
				util.Error('Error closing %s: %s'%(self.which_service, j))

	def view(self):
		try:
			while True:
				self.dump = True
		except KeyboardInterrupt:
			self.dump = False
			return

	def shutdown(self):
		util.Msg('Shutting %s service down..'%self.which_service)
		if self.running:
			self.running = False
		if self.log_data:
			self.log(False, None)
		util.Msg("%s shutdown."%self.which_service)
		util.debug('%s shutdown.'%self.which_service)
