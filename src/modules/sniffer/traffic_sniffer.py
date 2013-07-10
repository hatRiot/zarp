from util import Error, test_filter
from sniffer import Sniffer
from scapy.all import *


class traffic_sniffer(Sniffer):
    """Simple sniffer for dumping host traffic
    """
    def __init__(self):
        super(traffic_sniffer, self).__init__('Traffic Sniffer')

    def initialize(self):
        """ Initialize sniffer """
        self.get_ip()
        while True:
            try:
                tmp = raw_input('[!] Enter filter or [enter] for all traffic: ')
                if len(tmp) > 2:
                    if not test_filter(tmp):
                        Error("Invalid filter given")
                        continue
                    self.sniff_filter = tmp
                tmp = raw_input('[!] Sniff traffic from %s.  Is this correct? '
                                                            % self.source)
                if 'n' in tmp.lower():
                    break

                if self.sniff_filter is None:
                    self.sniff_filter = "src {0} or dst {0}".format(self.source)
                else:
                    self.sniff_filter = "src {0} or dst {0} and {1}" \
                                    .format(self.source, self.sniff_filter)
                self.run()
                break
            except KeyboardInterrupt:
                return
            except Exception, j:
                Error('Error with sniffer: %s' % j)
                return
        return self.source

    def dump(self, pkt):
        """ Sniffer callback; print summary """
        if not pkt is None:
            self.log_msg(pkt.summary())

    def session_view(self):
        """Overriden to include filter"""
        return "%s [%s]" % (self.source, self.sniff_filter)
