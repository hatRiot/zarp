import util
import socket
from service import Service
from threading import Thread


class ftp(Service):
    def __init__(self):
        super(ftp, self).__init__('FTP Server')
        self.usr = None
        self.pwd = None
        self.server_socket = None
        self.config.update({"motd":{"type":"str", 
                                  "value":"b4ll4stS3c FTP Server v1.4",
                                  "required":False,
                                  "display":"Displayed MOTD"}
                        })
        self.info = """
                    Emulates a single threaded FTP server.
                    """

    def response(self, con, code, txt):
        """ Format a response to the client """
        con.send('%d %s\r\n' % (code, txt))

    def process_com(self, con, data):
        """ Process the incoming request; logs the
            username/password and denies access
        """
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

    def initialize_bg(self):
        """ Initialize as a background process
        """
        util.Msg('Starting FTP server...')
        self.server_thread = Thread(target=self.initialize)
        self.server_thread.start()
        return True

    def initialize(self):
        """ Initialize; blocking
        """
        self.running = True
        self.server_sock = socket.socket()
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_sock.bind(('', 21))
        except:
            util.Error('Cannot bind to address.')
            return

        self.server_sock.settimeout(3)
        self.server_sock.listen(1)
        try:
            while self.running:
                try:
                    conn, addr = self.server_sock.accept()
                except KeyboardInterrupt:
                    return
                except:
                    continue
                self.log_msg('Connection from %s' % str(addr))
                self.response(conn, 220, self.config['motd']['value'])

                while self.running:
                    try:
                        data = conn.recv(256)
                        if len(data) > 0 and not self.process_com(conn, data):
                            break
                    except socket.error:
                        break
                self.log_msg("Received \033[32m%s:%s\033[33m from connection."
                                                    % (self.usr, self.pwd))
                self.log_msg("\'%s\' disconnected.\n" % (addr[0]))
                conn.close()
        except KeyboardInterrupt:
            self.running = False
        except socket.error:
            # timeout/broken pipe
            pass
        except Exception:
            pass

    def cli(self, parser):
        """ establish cli options
        """
        parser.add_argument('--ftp', help='FTP server', action='store_true',
                                    default=False, dest=self.which)
