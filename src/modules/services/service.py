from module import ZarpModule
import abc

class Service(ZarpModule):
	"""Abstract service
	"""
	__metaclass__ = abc.ABCMeta

	def __init__(self, which):
		super(Service, self).__init__(which)

	@abc.abstractmethod
	def initialize_bg(self):
		""" When services are initialized from the CLI,
			they need to be run in their own thread
		"""
		raise NotImplementedError
