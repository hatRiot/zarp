import abc

#
# Abstract poisoner
# Very minimal at this stage as a 'poisoner' is loosely defined.
#

class Poison(object):
	def __init__(self, which):
		self.which = which

	@abc.abstractmethod
	def initialize(self):
		pass
	
	@abc.abstractmethod
	def shutdown(self):
		pass

	#
	# Session view
	#
	def session_view(self):
		return self.which
