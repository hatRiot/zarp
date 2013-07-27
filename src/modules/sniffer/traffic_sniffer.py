from util import Error, test_filter
from sniffer import Sniffer
from scapy.all import *


class traffic_sniffer(Sniffer):
    def __init__(self):
        super(traffic_sniffer, self).__init__('Traffic Sniffer')
        self.config.update({"filter":{"type":"str",
                                      "value":"src {0} or dst {0}".format(
                                              self.config['target']['value']),
                                      "required":False,
                                      "display":"Traffic filter"}
                            })
        self.info = """
                    This module can be used as a simple traffic sniffer.
                    A filter option is provided to use tcpdump/scapy-esque
                    filter syntax to narrow down the information provided."""

    def initialize(self):
        """ Initialize sniffer """
        if test_filter(self.config['filter']['value']):
            self.sniff_filter = self.config['filter']['value']
            self.run()
        else:
            Error("Error with provided filter.")
            return False
        return True

    def dump(self, pkt):
        """ Sniffer callback; print summary
        """
        if not pkt is None:
            self.log_msg(pkt.summary())

    def session_view(self):
        """ Overridden to include filter
        """
        return "%s [%s]" % (self.source, self.sniff_filter)
