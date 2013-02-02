import abc

#
# Abstract parameter
#
class Parameter(object):
	def __init__(self, service):
		self.which_service = service

	@abc.abstractmethod
	def initialize():
		pass
