from module import ZarpModule
from util import init_app
from re import search
import abc

class DoS(ZarpModule):
	"""Abstract denial of service class"""
	__metaclass__ = abc.ABCMeta

	def __init__(self, which):
		super(DoS, self).__init__(which)
		self.target = None
	
	@abc.abstractmethod
	def initialize():
		raise NotImplementedError	

	def is_alive(self):
		"""Check if the target is alive"""
		if not self.target is None:
			rval = init_app('ping -c 1 -w 1 %s'%self.target, True)
			up = search('\d.*? received', rval)
			if search('0', up.group(0)) is None:
				return True
		return False

	def get_ip(self):
		"""Fetch the target IP address"""
		while True:
			try:
				tmp = raw_input('[!] Enter target address: ')
				if len(tmp.split('.')) is 4:
					self.target = tmp
					break
				else: util.Error("Please enter a valid IP address")
			except KeyboardInterrupt:
				self.target = None
				return
			except:
				pass
