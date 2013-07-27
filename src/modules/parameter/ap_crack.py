import util
import os
from parameter import Parameter


class ap_crack(Parameter):
    """ Interfaces with Wifite to crack APs
    """
    def __init__(self):
        super(ap_crack, self).__init__('APCrack')
        self.config.update({"mode":{"type":"int", 
                                    "value":1,
                                    "required":True, 
                                    "display":"Mode to crack",
                                    "opts":['WEP', 'WPA', 'WPS']}
                           })
        self.info = """
                    Harnesses the power of Wifite to crack WEP, WPA, and WPS
                    devices."""

    def initialize(self):
        choice = self.config['mode']['value']

        cmd = []
        while True:
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
                break
            else:
                return False

        try:
            os.system(' '.join(cmd))
        except KeyboardInterrupt:
            pass
        except Exception, j:
            util.Error('Error initializing Wifite: %s' % j)

