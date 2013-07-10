import socket
from datetime import datetime
from util import Error
from scapy.all import *
from scanner import Scanner


class net_map(Scanner):
    """ Perform an ARP scan of the network
    """
    def __init__(self):
        self.net_mask = ''
        self.available_hosts = {}
        self.fingerprint = False
        self.rev_lookup = False
        super(net_map, self).__init__('NetMap')

    def initialize(self):
        try:
            self.net_mask = raw_input('[!] Enter netmask: ')
            tmp = raw_input('[!] Fingerprint? [y]: ')
            if tmp == '' or 'y' in tmp.lower():
                self.fingerprint = True
        except Exception:
            return
        self.scan_block()

    def scan_block(self):
        """ ARPing the local network
        """
        conf.verb = 0
        print '[!] Beginning host scan with netmask %s...' % (self.net_mask)
        try:
            start = datetime.now()
            (ans, unans) = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.net_mask),timeout=1, inter=0.1,multi=True)
            elapsed = (datetime.now() - start).seconds
            print '[!] Scan of %s completed in %s seconds with %d hosts responding.'%(self.net_mask,elapsed,len(ans))
            for s, r in ans:
                ip = r[ARP].getfieldval('psrc')
                mac = r[ARP].getfieldval('hwsrc')
                if self.fingerprint:
                    host = ''
                    try:
                        if hasattr(socket, 'setdefaulttimeout'):
                            socket.setdefaulttimeout(3)
                        host = socket.gethostbyaddr(ip)[0]
                    except:
                        host = ''
                    print "\t%s : %s (%s)" % (mac, ip, host)
                    self._dbhost(mac, ip, host)
                else:
                    print '\t%s : %s' % (mac, ip)
                    self._dbhost(mac, ip, '')
                self.available_hosts[mac] = ip
        except Exception:
            Error('Error with net mask.  Cannot scan given block.')
            return
        print '\n'

    def view(self):
        """ Dump previous scan results
        """
        print '\n\t\033[32m[!] Available hosts in range %s:\033[0m' \
                                                            % self.net_mask
        for mac in self.available_hosts.keys():
            print '\t%s : %s' % (mac, self.available_hosts[mac])

    def cli(self, parser):
        """ Add CLI options
        """
        parser.add_argument('-s', help='Network scanner',
                        action='store_true', dest=self.which)
