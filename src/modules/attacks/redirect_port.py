from attack import Attack
import util
from zoption import Zoption


class redirect_port(Attack):
    def __init__(self):
        super(redirect_port, self).__init__("redirect_port")
        self.iptable = "iptables -t nat -A PREROUTING -p tcp --dport {0} -j REDIRECT --to-port {1}"
        self.config.update({"source_port": Zoption(type="int", value=80, required=True, display="Source port"),
                            "dest_port": Zoption(type="int", value=8080, required=True, display="Destination port")})
        self.config.update({})
        self.running = False
        self.info = """
                    Redirects inbound TCP traffic on source port to destination port on localhost
                    """

    def modip(self, enable=True):
        """
        Enable or disable the iptable rule
        """
        to_exec = self.iptable.format(self.config['source_port'].value, self.config['dest_port'].value)
        if enable:
            util.init_app(to_exec)
        else:
            util.init_app(to_exec.replace('-A', '-D'))

    def initialize(self):
        util.Msg("Starting redirect_port...")

        self.modip()

        self.running = True

        util.Msg("Redirection to from TCP port {0} to {1}...")

        return True

    def shutdown(self):
        util.Msg("Shutting down RedirectPort...")
        self.modip(False)

    def session_view(self):
        """
        Return information about the redirections
        """
        return "Redirect from {0} to {1}".format(self.config['source_port'].value, self.config['dest_port'].value)
