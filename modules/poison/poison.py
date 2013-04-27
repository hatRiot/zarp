from module import ZarpModule
import abc

""" Abstract poison module
"""
class Poison(ZarpModule):
	def __init__(self, which):
		super(Poison,self).__init__(which)

	@abc.abstractmethod
	def initialize(self):
		raise NotImplementedError
