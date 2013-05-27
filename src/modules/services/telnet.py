import util
import socket
from colors import color
from service import Service
from threading import Thread

class telnet(Service):
	""" Simple telnet emulator; just grabs a username/password
		and denies access.  Could be extended to be a sort of
		honeypot system.
	"""
	def __init__(self):
		self.server_thread = None
		self.server_socket = None
		super(telnet,self).__init__('telnet server')

	def response(self, con, msg):
		""" Respond to connection
		"""
		con.send('%s'%msg)

	def initialize_bg(self):
		""" initialize background service
		"""
		util.Msg('Starting telnet service...')
		self.server_thread = Thread(target=self.initialize)
		self.server_thread.start()
		return True

	def initialize(self):
		""" initialize; blocking
		"""
		self.running = True
		self.server_sock = socket.socket()
		self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		try: self.server_sock.bind(('', 23))
		except: 
			util.Error('Cannot bind to address.')
			return

		self.server_sock.settimeout(3)
		self.server_sock.listen(1)
		try:
			while self.running:
				try: con, addr = self.server_sock.accept()
				except KeyboardInterrupt: return
				except: continue

				self.log_msg('Connection from %s\n'%str(addr))
				con.recv(256) #junk

				while self.running:
					try:
						# username/password prompt 
						self.response(con, 'Unified Username: ')
						username = con.recv(256).strip().replace('\n', '')
						if len(username) < 1: continue

						self.response(con, 'Unified Password: ')
						password = con.recv(256).strip().replace('\n','')
						if len(password) < 1: continue

						self.response(con, 'Invalid Credentials\r\n')
						self.log_msg('Received %s%s:%s%s from connection.'%
										(color.GREEN,username,password,color.YELLOW))
						break
					except socket.error: break
				con.close()
				self.log_msg('%s disconnected.\n'%str(addr))
		except: self.server_sock.close()

	def cli(self, parser):
		""" initialize CLI options
		"""
		parser.add_argument('--telnet', help='Telnet server', action='store_true', 
									default=False, dest=self.which)
