from module import ZarpModule
from scapy.all import sniff
from threading import Thread
import util
import config
import abc


class Sniffer(ZarpModule):
    """ Abstract sniffer """
    __metaclass__ = abc.ABCMeta

    def __init__(self, which):
        self.source = config.get('ip_addr')   # source to sniff from
        self.sniff_filter = None              # filter for the traffic sniffer
        # initialize thread
        self.sniff_thread = Thread(target=self.traffic_sniffer)
        super(Sniffer, self).__init__(which)

    @abc.abstractmethod
    def dump(self, pkt):
        raise NotImplementedError

    def session_view(self):
        """ Session viewer returns source
        """
        return '%s' % self.source

    def traffic_sniffer(self):
        """ Sniff traffic with the given filter.
            If sniff_filter is not set, an exception is raised
        """
        if self.sniff_filter is None:
            raise NotImplementedError, "sniff_filter not initialized!"

        sniff(filter=self.sniff_filter, store=0, prn=self.dump,
                    stopper=self.stop_callback, stopperTimeout=3)

    def get_ip(self):
        """ Retrieve IP address from user to sniff for"""
        while True:
            try:
                tmp = raw_input('[!] Enter address to listen on [%s]: '
                                                                % self.source)
                if tmp.strip() != '':
                    if len(tmp.split('.')) >= 4:
                        self.source = tmp
                break
            except KeyboardInterrupt:
                return
            except:
                continue

    def stop_callback(self):
        """ Initiate a sniffer shutdown"""
        if self.running:
            return False
        util.debug('%s shutting down...' % self.which)
        return True

    def run(self):
        """Friendly handler"""
        try:
            self.running = True
            self.sniff_thread.start()
        except Exception, e:
            util.Error('Error with sniffer: %s' % (e))
