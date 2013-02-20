import importlib
import routers
import util
from routers.router_vuln import RouterVuln
from parameter import Parameter

class router_pwn(Parameter):
	""" Router pwn module for managing and pwning routers
	"""

	def __init__(self):
		self.routers = {}
		super(router_pwn,self).__init__('RouterPwn')

	def load(self):
		"""Load router modules"""
		for router in routers.__all__:
			# relative to zarp.py
			mod = importlib.import_module('modules.parameter.routers.%s'%router)
			self.routers[router] = []
			for vuln in mod.__all__: 
				v = importlib.import_module('modules.parameter.routers.%s.%s'%(router,vuln))
				if not hasattr(v, '__router__') or not hasattr(v,'__vuln__'):
					continue
				self.routers[router].append(v)	

	def initialize(self):
		self.load()
		while True:
			choice = util.print_menu([x for x in self.routers.keys()])
			if choice is 0:
				del(self.routers)
				break
			elif choice is -1 or choice > len(self.routers.keys()):
				pass
			else:
				router = self.routers[self.routers.keys()[choice-1]]
				while True:
					# print router modules
					choice = util.print_menu(['%s - %s'%(x.__router__,x.__vuln__) for x in router]) 
					if choice is 0:
						break
					elif choice is -1 or choice > len(router):
						pass
					else:
						tmp = util.get_subclass(router[choice-1], RouterVuln)()
						tmp.run()
