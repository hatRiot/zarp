import abc
from util import init_app
from re import search

#
# Abstract DoS
#
class DoS(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self, which):
		self.which = which
		self.target = None
	
	@abc.abstractmethod
	def initialize():
		pass

	#
	# Check if the target is responding
	#
	def is_alive(self):
		if not self.target is None:
			rval = init_app('ping -c 1 -w 1 %s'%addr[0], True)
			up = search('\d.*? received', rval)
			if search('0', up.group(0)) is None:
				return True
		return False
