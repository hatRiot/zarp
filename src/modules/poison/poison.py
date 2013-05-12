from module import ZarpModule
import util
import abc

""" Abstract poison module
"""
class Poison(ZarpModule):
	def __init__(self, which):
		super(Poison,self).__init__(which)

	
	def test_stop(self):
		""" Callback for stopping a sniffer
		"""
		if self.running:
			return False
		util.debug("Stopping sniffer threads for %s.."%self.which)
		return True
