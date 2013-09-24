import util
from time import sleep
from threading import Thread
from service import Service
from zoption import Zoption


class access_point(Service):
    def __init__(self):
        super(access_point, self).__init__('Access Point')
        self.mon_adapt = None
        del self.config["port"]
        self.config.update({"ap_essid":Zoption(type = "str", 
                                        value = "zoopzop",
                                        required = False, 
                                        display = "Spoofed AP name")
                           })
        self.info = """
                    Implements a fake wireless access point to execute
                    client attacks or set up a wireless mitm that forwards
                    traffic to another device.

                    Passthru currently not working; todo.
                    """

    def initialize_bg(self):
        """Initialize in background thread"""
        if not util.check_program('airbase-ng'):
            util.Error('\'airbase-ng\' not found in local path.')
            return False

        util.Msg('Initializing access point..')
        thread = Thread(target=self.initialize)
        thread.start()

        sleep(2)
        if self.running:
            return True
        else:
            return False

    def initialize(self):
        """Initialize AP"""
        if not util.check_program('airbase-ng'):
            util.Error('\'airbase-ng\' not found in local path.')
            return False

        self.running = True
        ap_proc = None

        try:
            self.mon_adapt = util.get_monitor_adapter()
            if self.mon_adapt is None:
                self.mon_adapt = util.enable_monitor()

            if self.mon_adapt is None:
                util.Error('Could not find a wireless card in monitor mode')
                self.running = False
                return None

            airbase_cmd = [
                        'airbase-ng',
                        '--essid', self.config['ap_essid'].value,
                        self.mon_adapt
                          ]
            ap_proc = util.init_app(airbase_cmd, False)
            util.Msg('Access point %s running.' % \
                                    self.config['ap_essid'].value)
            raw_input()    # block
        except KeyboardInterrupt:
            self.running = False
        except Exception, er:
            util.Error('Error with wireless AP: %s' % er)
        finally:
            util.disable_monitor()
            util.kill_app(ap_proc)

    def cli(self, parser):
        """ establish CLI options
        """
        parser.add_argument('--wap', help='Wireless access point',
                        action='store_true', default=False, dest=self.which)
