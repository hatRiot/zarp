from module import ZarpModule
import abc

""" Abstract parameter
"""

class Parameter(ZarpModule):
	def __init__(self, which):
		super(Parameter,self).__init__(which)

	@abc.abstractmethod
	def initialize():
		raise NotImplementedError
