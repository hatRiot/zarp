import os
import util
from scanner import Scanner


class ap_scan(Scanner):
    """ Scan for wireless APs.  Useful when searching for WEP or unprotected
        APs.  Essentially an interface to airodump-ng.
    """
    def __init__(self):
        self.channel = None
        super(ap_scan, self).__init__('AP Scan')

    def initialize(self):
        """ Initialize the scanner
        """
        try:
            if not util.check_program('airmon-ng'):
                util.Error('airomon-ng not installed.  Please install to continue.')
                return None
            util.Msg('(ctrl^c) when finished.')
            iface = util.get_monitor_adapter()
            if iface is None:
                util.Msg('No devices found in monitor mode.  Enabling...')
                iface = util.enable_monitor(self.channel)
            util.debug('Using interface %s' % iface)
            self.ap_scan(iface)
        except Exception:
            return

    def ap_scan(self, adapt):
        """ Sniff on the monitoring adapter
        """
        try:
            util.Msg('Scanning for access points...')
            if self.channel is None:
                os.system('airodump-ng %s' % adapt)
            else:
                os.system('airodump-ng --channel %s %s' % (self.channel, adapt))
        except Exception, j:
            util.Error('Error scanning: %s' % j)
        finally:
            util.disable_monitor()

    def cli(self, parser):
        """ Add the CLI options
        """
        parser.add_argument('-w', help='Wireless AP Scan', action='store_true',
                            default=False, dest=self.which)
