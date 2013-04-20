import abc

class Scanner(object):
	"""Abstract scanner
	"""
	__metaclass__ = abc.ABCMeta

	def __init__(self, which):
		self.which = which
		self.target = None

	@abc.abstractmethod
	def initialize():
		pass

	def is_alive(self):
		""" Check if the target is responding
		"""
		if not self.target is None:
			rval = init_app('ping -c 1 -w 1 %s'%addr[0], True)
			up = search('\d.*? received', rval)
			if search('0', up.group(0)) is None:
				return True
		return False
