import util, socket
from threading import Thread

#
# emulate a single-threaded FTP service
#
class FTPService():
	def __init__(self):
		self.motd = 'b4ll4stS3c FTP Server v1.4'
		self.usr = None
		self.pwd = None
		self.running = False
		self.serv_sock = None
		self.dump = False
		self.log_data = False
		self.log_file = None
	
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
		cmd = data.split(' ')[0].strip()
		if cmd == 'USER':
			usr = data.split(' ')[1]
			if usr is None:
				self.response(con, 503, 'Incorrect username.')
			self.usr = usr.rstrip()
			self.response(con, 331, 'Specify password.')
		elif cmd == 'PASS':
			psswd = data.split(' ')[1]
			if psswd is None:
				self.response(con, 503, 'Incorrect password.')
			self.pwd = psswd.rstrip()
			self.response(con, 530, 'Incorrect credentials')
			return False
		else:
			self.response(con, 530, 'Please login first.')
			return False
		return True

	# init as a background process
	def initialize_bg(self):
		util.Msg('Starting FTP server...')
		ftp_thread = Thread(target=self.initialize)
		ftp_thread.start()
		return

	# le init
	def initialize(self):
		self.running = True
		self.serv_sock = socket.socket()
		self.serv_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		try:
			self.serv_sock.bind(('', 21))
		except:
			util.Error('Cannot bind to address.')
			return

		self.serv_sock.listen(1)
		try:
			while self.running:
				conn, addr = self.serv_sock.accept()
				if self.dump: util.Msg('Connection from %s'%str(addr))
				if self.log_data: self.log_file.write('Connection from %s\n'%str(addr))
				self.response(conn, 220, self.motd)

				while self.running: 
					try:
						data = conn.recv(256)
						if len(data) > 0 and not self.process_com(conn, data):
							break
					except socket.error:
						break

				if self.dump: 
					util.Msg("Received '\033[32m%s:%s\033[33m' from connection."%(self.usr, self.pwd))
				if self.log_data: 
					self.log_file.write('Received \'%s:%s\' from %s.\n'%(self.usr, self.pwd, str(addr)))
	
				if self.dump: util.Msg('\'%s\' disconnected.\n'%(addr[0]))
				conn.close()
		except KeyboardInterrupt:
			self.running = False	
		except socket.error:
		 	# timeout/broken pipe
	 		pass
		except Exception, j:
			pass	

		self.serv_sock.close()

	#
	# dump connection information
	#
	def view(self):
		try:
			while True:
				self.dump = True
		except KeyboardInterrupt:
			self.dump = False
			return

	#
	# Start logging, or stop logging
	# OPT for logging NOT OPT to disable
	#
	def log(self, opt, log_loc):
		if opt and not self.log_data:
			try:
				util.debug('Starting FTP logger')
				self.log_file = open(log_loc, 'w+')
			except Exception, j:
				util.Error('Error opening log file: %s'%j)
				self.log_file = None
				return
			self.log_data = True
		elif not opt and self.log_data:
			try:
				self.log_file.close()
				self.log_file = None
				self.log_data = False
				util.debug('FTP logger shutdown complete.')
			except Exception, j:
				util.Error('Error closing logger: %s'%j)

	#
	# shutdown ftp service
	#
	def shutdown(self):
		util.Msg('Shutting FTP service down')
		self.running = False
		try:
			self.serv_sock.shutdown(2)
		except Exception, r:
			print r
		if self.log_data:
			self.log(False, None)
		util.Msg('FTP shutdown.')
