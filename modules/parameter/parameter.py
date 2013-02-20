import abc

#
# Abstract parameter
#
class Parameter(object):
	def __init__(self, service):
		self.which = service

	@abc.abstractmethod
	def initialize():
		pass
