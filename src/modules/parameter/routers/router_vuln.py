import abc

class RouterVuln(object):
	"""Abstract router vulnerability"""
	__metaclass__ = abc.ABCMeta

	def __init__(self):
		"""Initialize a default router IP and fetch IP from user"""
		self.ip = '192.168.1.1'
		self.fetch_ip()
	
	@abc.abstractmethod
	def run(self):
		"""Runner for the menus"""
		pass

	def fetch_ip(self):
		"""Fetch the router IP"""
		while True:
			try:
				tmp = raw_input('[!] Enter address of router [%s]: '%self.ip)
				if len(tmp) > 2:
					self.ip = tmp
				break
			except KeyboardInterrupt:
				return
			except:
				continue
