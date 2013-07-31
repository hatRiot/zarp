from module import ZarpModule
from util import init_app
from re import search
from util import Error
from zoption import Zoption
import abc


class DoS(ZarpModule):
    """Abstract denial of service class"""
    __metaclass__ = abc.ABCMeta

    def __init__(self, which):
        super(DoS, self).__init__(which)
        self.config.update({"target":Zoption(type = "ip", 
                                             value = None,
                                             required = True, 
                                             display = "Target to DoS")
                           })

    def is_alive(self):
        """Check if the target is alive"""
        if not self.config['target'].value is None:
            rval = init_app('ping -c 1 -w 1 %s' % \
                            self.config['target'].value, True)
            up = search('\d.*? received', rval)
            if search('0', up.group(0)) is None:
                return True
        return False