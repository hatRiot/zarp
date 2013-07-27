import socket
from datetime import datetime
from util import Error
from scapy.all import *
from scanner import Scanner


class net_map(Scanner):
    def __init__(self):
        super(net_map, self).__init__('NetMap')
        self.available_hosts = {}
        self.config.update({"net_mask":{"type":"ipmask", 
                                        "value":None,
                                        "required":True, 
                                        "display":"Netmask to scan"},
                        "fingerprint":{"type":"bool", 
                                        "value":False,
                                        "required":False, 
                                        "display":"Fingerprint the host"}
                           })
        self.info = """
                    Performs an ARP scan of the local network.
                    """

    def initialize(self):
        self.scan_block()

    def scan_block(self):
        """ ARPing the local network
        """
        net_mask = self.config['net_mask']['value']
        conf.verb = 0
        print '[!] Beginning host scan with netmask %s...' % (net_mask)
        try:
            start = datetime.now()
            (ans, unans) = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net_mask),timeout=1, inter=0.1,multi=True)
            elapsed = (datetime.now() - start).seconds
            print '[!] Scan of %s completed in %s seconds with %d hosts responding.'%(net_mask,elapsed,len(ans))
            for s, r in ans:
                ip = r[ARP].getfieldval('psrc')
                mac = r[ARP].getfieldval('hwsrc')
                if self.config['fingerprint']['value']:
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
                                            % self.config['net_mask']['value']
        for mac in self.available_hosts.keys():
            print '\t%s : %s' % (mac, self.available_hosts[mac])

    def cli(self, parser):
        """ Add CLI options
        """
        parser.add_argument('-s', help='Network scanner',
                        action='store_true', dest=self.which)
