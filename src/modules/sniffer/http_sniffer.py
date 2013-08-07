import util
import re
from collections import namedtuple
from config import pptable
from sniffer import Sniffer
from scapy.all import *
from zoption import Zoption


class http_sniffer(Sniffer):
    def __init__(self):
        super(http_sniffer, self).__init__('HTTP Sniffer')
        self.sessions = {}
        self.config.update({"verb":Zoption(type = "int",
                                    value = 1,
                                    required = False,
                                    display = "Output verbosity",
                                    opts = ['Site Only', 'Request String', 
                                             'Request and Payload',
                                             'Session IDs', 'Custom Regex'
                                            ]),
                            "regex":Zoption(type = "regex",
                                     value = None,
                                     required = False,
                                     display = "Regex for level 5 verbosity")
            })
        self.info = """ 
                    The HTTP sniffer is a fairly robust sniffer module that
                    supports various methods of parsing up data, including:
                        [*] Site Only
                            This level will only parse out the website/host in
                            the packet's request.
                        [*] Request string
                            This will parse out and store the entire request string.
                        [*] Request and Payload
                            Included in this level from the last is the actual
                            payload of the request.
                        [*] Session ID
                            Still a work in progress, but this will attempt to
                            parse out MOST standard session ID variables.  This
                            will store them in a pretty table that you can drag up
                            when viewing the module.
                        [*] Custom regex
                            This allows the user to insert a custom regex string,
                            in Python form, that will then parse and display
                            matches."""

    def initialize(self):
        """Initialize the sniffer"""
        self.sniff_filter = "tcp and dst port 80 and src %s" % \
                                        self.config['target'].value
        self.run()
        util.Msg("Running HTTP sniffer...")
        return True

    def manage_sessions(self, data):
        """ Parse and manage session IDs.
            Return this requests ID
        """
        # is there a session ID here?
        if 'session' in data.lower():

            # grab the host
            host = re.findall('Host: (.*)', data)
            if len(host) > 0:
                host = host[0]
            else:
                return None

            # grab the session; there are different ways this can be formatted in
            # the payload.  this should, for the most part, get the popular ones.
            # Probably will have a bunch of false positives, so this'll be tweaked.
            session_id = re.findall('.*?sess.*?[:|=](..*?)(&|;|$|:|\n| )', data.lower())
            if len(session_id) > 0:
                session_id = session_id[0][0]
            else:
                return None

            self.sessions[host] = session_id
            return session_id

    def pull_output(self, pkt):
        """ Based on what verbosity level is set, parse
            the packet and return formatted data.
        """
        verb = self.config['verb'].value
        data = pkt.getlayer(Raw).load
        if verb is 1:
            # parse the site only
            data = re.findall('Host: (.*)', data)
            if len(data) > 0:
                data = data[0]
            else:
                data = None
        elif verb is 2:
            data = data.split('\n')
            if len(data) > 0:
                data = data[0]
            else:
                data = None
        elif verb is 3:
            pass
        elif verb is 4:
            data = self.manage_sessions(data)
        elif verb is 5:
            data = self.config['regex'].value.search(data)
            if not data is None:
                data = data.group(0)
        return data

    def dump(self, pkt):
        """ Dump the formatted payload """
        try:
            if pkt.haslayer(Raw):
                data = self.pull_output(pkt)
                if not data is None:
                    self.log_msg(data)
        except Exception, e:
            util.Error('%s' % (e))
            return

    def view(self):
        """ Overload view so we can print out
            sessions in a pretty table.
        """
        if self.config['verb'].value is 4:
            Setting = namedtuple('Setting', ['Host', 'SessionID'])
            table = []
            for i in self.sessions.keys():
                data = Setting(str(i).strip(), str(self.sessions[i]).strip())
                table.append(data)
            pptable(table)
        else:
            super(http_sniffer, self).view()

    def session_view(self):
        """ Overloaded to return both the sniffed
            address and the verbosity.
        """
        return '%s [%s]' % (self.config['target'], self.config['verb'].value \
                                            [self.config['verb'].value-1])
