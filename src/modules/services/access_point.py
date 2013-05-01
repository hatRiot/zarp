import util, config
import os
from threading import Thread
from service import Service

class access_point(Service):
	"""Implements a fake wireless access points that supports passthru; or,
	   forwarding traffic from the fake AP to another iface.
	"""

	def __init__(self):
		self.ap_essid = 'zoopzop'
		self.mon_adapt = None
		super(access_point,self).__init__('Access Point')
	
	def initialize_bg(self):
		"""Initialize in background thread"""
		if not util.check_program('airbase-ng'):
			util.Error('\'airbase-ng\' not found in local path.')
			return False

		while True:
			try:
				tmp = raw_input('[!] Enter ESSID [%s]: '%self.ap_essid)
				if len(tmp) > 2:
					self.ap_essid = tmp
				break
			except KeyboardInterrupt:
				break
			except:
			 	continue

		util.Msg('Initializing access point..')
		thread = Thread(target=self.initialize)
		thread.start()
		return True

	def initialize(self):
		"""Initialize AP"""
		if not util.check_program('airbase-ng'):
			util.Error('\'airbase-ng\' not found in local path.')
			return False
	
		self.running = True
		ap_proc = None
			
		try:
			self.mon_adapt = util.get_monitor_adapter()
			if self.mon_adapt is None:
				self.mon_adapt = util.enable_monitor()
		
			if self.mon_adapt is None:
				util.Error('Could not find a wireless card in monitor mode')
				return None

			airbase_cmd = [
						'airbase-ng',
						'--essid', self.ap_essid,
						self.mon_adapt
						  ]
			ap_proc = util.init_app(airbase_cmd, False)
			util.Msg('Access point %s running.'%self.ap_essid)
			raw_input()	# block	
		except KeyboardInterrupt:
			self.running = False
		except Exception, er:
			util.Error('Error with wireless AP: %s'%er)
		finally:
			util.disable_monitor()
			util.kill_app(ap_proc)
