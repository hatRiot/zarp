from re import compile, UNICODE
from os import chown
from pwd import getpwnam
import util
import abc

""" Abstract module
"""
class ZarpModule(object):
	__metaclass__ = abc.ABCMeta
	def __init__(self, which):
		self.running   = False       # is the module running?
		self.log_data  = False       # are we logging to a file? 
		self.log_file  = None        # where are we logging out to?
		self.which     = which       # who or what are we?
		self.dump_data = False       # are we printing to console?
		self.scrub     = compile(r"\033\[\d{2}m")    # remove color codes
	
	@abc.abstractmethod
	def initialize(self):
		"""Initialization method that should be
		   implemented at the module level
		"""
		raise NotImplementedError	

	def session_view(self):
		""" This is what's displayed in the session 
			viewer; may be overriden to return some
			customized view
		"""
		return self.which

	def log_msg(self, msg):
		""" Log message to screen or file 
		"""
		if self.dump_data:
			util.Msg(msg)
		if self.log_data:
			msg = self.scrub.sub('', msg)             # remove color codes
			msg = msg if '\n' in msg else msg + '\n'  # add a newline if it's not there
			self.log_file.write(msg)
			self.log_file.flush()

	def log(self, opt, log_loc=None):
		""" Logging function for enabling or disabling
			the logging of messages to a file
		"""
		if opt and not self.log_data:
			try:
				util.debug('Starting %s logger...')
				self.log_file = open(log_loc, 'w+')

				# chown the log file
				run_usr = util.get_run_usr()
				uid     = getpwnam(run_usr).pw_uid
				gid     = getpwnam(run_usr).pw_gid
				chown(log_loc, uid, gid)
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
				util.debug('%s logger shutdown complete.'%self.which)
			except Exception, j:
				util.Error('Error closing %s: %s'%(self.which, j))

	def view(self):
		""" Used to enter a state of 'focus'; i.e.
			the user wants to see status updates, informational
			messages, etc.
		"""
		try:
			util.Msg('[enter] when finished')
			util.Msg('Dumping output from \'%s\'...'%self.which)
			self.dump_data = True
			raw_input()
			self.dump_data = False
		except KeyboardInterrupt:
			self.dump_data = False
			return

	def shutdown(self):
		""" Shut down the module cleanly
		"""
		util.Msg('Shutting \'%s\' down..'%self.which)

		if self.running:  self.running = False
		if self.log_data: self.log(False)

		util.Msg("%s shutdown."%self.which)
		util.debug('%s shutdown.'%self.which)
