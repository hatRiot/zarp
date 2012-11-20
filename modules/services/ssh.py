import util, os
import socket, ssl

#
# emulate a basic SSH service; store usernames/passwords but reject them all.
# Certs toot.
#
class SSHService:
	def __init__(self):
		self.running = False

	#
	# remove generated key/cert file 
	#
	def cleanup(self):
		os.system('rm -f tmpkey.pem cert.pem')

	def initialize(self):
		util.Msg('Initializing SSH service...')
		util.debug('SSL: %s'%ssl.OPENSSL_VERSION)

		# test for openssl first
		if not util.check_program('openssl'):
			util.Error("OpenSSL required to generate cert and key files.")
			return
		else:
			# generate a tmp cert/key file
			tmp = util.init_app('openssl req -x509 -nodes -days 1 -subj \'/C=US/ST=ttT/L=Ttt/CN=ttT\' -newkey rsa:1024 -keyout tmpkey.pem -out cert.pem', True)
		sock = socket.socket()
		try:
			sock.bind(('', 22))
		except:
			util.Error('Could not bind to address.')
			return
		self.running = True
		sock.listen(1)

		try:
			while self.running:
				con, addr = sock.accept()
				util.Msg('Connection from %s'%str(addr))
				ssl_con = ssl.wrap_socket(con, server_side=True,
									certfile='cert.pem', keyfile='tmpkey.pem',
									ssl_version=ssl.PROTOCOL_SSLv23)
				util.debug('Performing SSL handshake...')
				ssl_con.do_handshake()
				data = ssl_con.read()
				print 'received: ', data
				while data:
					data = ssl_con.read()
					print data
				ssl_con.shutdown(socket.SHUT_RDWR)
				ssl_con.close()
		except KeyboardInterrupt:
			pass
		except Exception, j:
			util.Error('Error: %s'%j)	
		self.cleanup()
