import util
import os
from parameter import Parameter


class ap_crack(Parameter):
    """ Interfaces with Wifite to crack APs
    """
    def __init__(self):
        self.cracks = ['WEP', 'WPA', 'WPS']
        super(ap_crack, self).__init__('APCrack')

    def initialize(self):
        cmd = []

        while True:
            choice = util.print_menu(self.cracks)
            if choice is 1:
                cmd = ['python',
                    'src/modules/parameter/wifite.py',
                    '--wep',
                    '--wept', '300',
                    '--nofakeauth']
                break
            elif choice is 2:
                cmd = ['python',
                    'src/modules/parameter/wifite.py',
                    '--wpa',
                    '--wpat', '10',
                    '--wpadt', '2']
                break
            elif choice is 3:
                cmd = ['python',
                    'src/modules/parameter/wifite.py',
                    '--wps',
                    '--wpst', '5',
                    '--wpsretry', '8']
            elif choice is 0:
                return
            else:
                continue
            break

        try:
            os.system(' '.join(cmd))
        except KeyboardInterrupt:
            pass
        except Exception, j:
            util.Error('Error initializing Wifite: %s' % j)

