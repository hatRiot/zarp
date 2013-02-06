from threading import Event
import util
import abc

#
# Abstract service
#

class Service(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self, which):
		self.which = which
		self.running = False
		self.log_data = False
		self.log_file = None
		self.dump = False

	#
	# When services are initialized from
	# the CLI gui, they need to be run in their
	# own thread.
	#
	@abc.abstractmethod
	def initialize_bg(self):
		pass

	@abc.abstractmethod
	def initialize(self):
		pass

	#
	# Session viewer
	#
	def session_view(self):
		return self.which

	#
	# logger; dumps to stdout or file handle
	#
	def log_msg(self, msg):
		if self.dump:
			util.Msg(msg)
		if self.log_data:
			self.log_file.write(msg)
			self.log_file.flush()

	#
	# setup service logging
	#
	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				util.debug('Starting %s logger...')
				self.log_file = open(log_loc, 'w+')
			except Exception, j:
				util.Error('Error opening log file for %s: %s'%
								(self.which, j))
				self.log_file = None
			self.log_data = True
		elif not opt and self.log_data:
			try:
				self.log_file.close()
				self.log_file = None
				self.log_data = False
				util.debug('%s shutdown complete.'%self.which)
			except Exception, j:
				util.Error('Error closing %s: %s'%(self.which, j))

	#
	# turn on output
	#
	def view(self):
		try:
			util.Msg('Dumping output from service \'%s\'...'%self.which)
			self.dump = True
			raw_input()
			self.dump = False
		except KeyboardInterrupt:
			self.dump = False
			return

	#
	# Shutdown the service
	#
	def shutdown(self):
		util.Msg('Shutting %s service down..'%self.which)
		if self.running:
			self.running = False
		if self.log_data:
			self.log(False, None)
		util.Msg("%s shutdown."%self.which)
		util.debug('%s shutdown.'%self.which)
