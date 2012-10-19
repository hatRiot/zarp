import util, socket

#
# emulate a single-threaded FTP service
#
class FTPService():
	def __init__(self):
		self.motd = 'b4ll4stS3c FTP Server v1.4\r\n'
		self.running = False
		self.usr = None
		self.pwd = None
	
	#
	# format a response to the client
	#
	def response(self, con, code, txt):
		con.send('%d %s\r\n'%(code, txt))
	
	#
	# process the incoming request; log username/password
	# combos and deny access
	#
	def process_com(self, con, data):
		cmd = data.split(' ')[0]
		if cmd == 'USER':
			usr = data.split(' ')[1]
			if usr is None:
				self.response(con, 503, 'Incorrect username.')
				return True
			self.usr = usr.rstrip()
			self.response(con, 331, 'Specify password.')
			return True
		elif cmd == 'PASS':
			psswd = data.split(' ')[1]
			if psswd is None:
				self.response(con, 503, 'Incorrect password.')
				return True
			self.pwd = psswd.rstrip()
			self.response(con, 530, 'Incorrect credentials')
			return False
		else:
			self.response(con, 530, 'Please login first.')
			return False
		return True

	# le init
	def initialize(self):
		util.Msg('Initializing FTP server...')
		self.running = True
		sock = socket.socket()
		try:
			sock.bind(('', 21))
		except:
			util.Error('Cannot bind to address.')
			return
		sock.listen(1)

		try:
			while self.running:
				conn, addr = sock.accept()
				util.Msg('Connection from %s'%str(addr))
				self.response(conn, 220, self.motd)
				while True:
					data = conn.recv(256)
					if len(data) > 0 and not self.process_com(conn, data):
						break
				util.Msg("Received '%s:%s' from connection."%(self.usr, self.pwd))
				conn.close()
		except KeyboardInterrupt:
			pass
		except Exception, j:
		 	util.Error('error with ftp service: '%j)
		sock.close()
	
	#
	# shutdown ftp service
	#
	def shutdown(self):
		util.debug('Shutting FTP service down')
		self.running = False
