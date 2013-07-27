import util
import socket
from scapy.all import *
from sniffer.sniffer import Sniffer


class Address:
    def __eq__(self, other):
        return self.ip == other

    def __init__(self):
        self.ip   = None
        self.mac  = None
        self.host = None


class passive_scan(Sniffer):
    def __init__(self):
        super(passive_scan, self).__init__('Passive Scanner')
        self.netmap = {}
        self.config.pop("target", None)
        self.info = """
                    Much like the passive scanner in Ettercap, this module 
                    was designed to passively map the network without 
                    spewing packets.  This will take some time, as we can 
                    only sniff what's coming at us.  One packet is sent out,
                    and that's for rDNS.
                    """

    def initialize(self):
        util.Msg('Initializing passive network map...')
        self.source = 'Passive Scanner'    # for session view
        self.sniff_filter = 'arp'          # pick out arp packets
        self.run()
        return 'Passive Scanner'

    def resolve(self, ip):
        """rdns with a timeout"""
        socket.setdefaulttimeout(2)
        try:
            host = socket.gethostbyaddr(ip)
        except:
            host = None
        if not host is None:
            host = host[0]
        return host

    def dump(self, pkt):
        """ Fish out broadcast packets and get src/dst
        """
        if 'ARP' in pkt:
            addr = None
            if pkt[ARP].op == 1:
                psrc = pkt[ARP].psrc
                if not psrc in self.netmap.keys():
                    addr = Address()
                    addr.ip   = psrc
                    addr.mac  = pkt[ARP].hwsrc
                    addr.host = self.resolve(psrc)

                    self.netmap[psrc] = addr
                elif self.netmap[psrc].ip != psrc and self.netmap[psrc].mac == pkt[ARP].src:
                     # IP changed
                    self.netmap[psrc].ip = psrc
            elif pkt[ARP].op == 2:
                pdst = pkt[ARP].pdst
                if not pdst in self.netmap.keys():
                    addr = Address()
                    addr.ip    = pdst
                    addr.mac   = pkt[ARP].hwdst
                    addr.host  = self.resolve(pdst)

                    self.netmap[pdst] = addr
                elif self.netmap[pdst].ip != pdst and self.netmap[pdst].mac == pkt[ARP].dst:
                    # IP changed
                    self.netmap[pdst].ip = pdst

            if addr is not None:
                self._dbhost(addr.mac, addr.ip, addr.host)

    def view(self):
        """Overridden Sniffer view
           since we just need to dump info
           out
        """
        if len(self.netmap) <= 0:
            util.Msg("No hosts yet mapped.")
        else:
            for address in self.netmap.keys():
                print '\t%s\t%s\t%s' % (self.netmap[address].ip,
                                      self.netmap[address].mac,
                                      self.netmap[address].host)
            util.Msg('\t %s hosts found.' % len(self.netmap))

    def session_view(self):
        """ We're a sniffer, but a scanner, so we don't
            really have a target.
        """
        return "Passive scanner"
