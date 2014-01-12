import importlib
import routers
import util
import stream
from parameter import Parameter


class router_pwn(Parameter):
    """ Router pwn module for managing and pwning routers
    """

    def __init__(self):
        super(router_pwn, self).__init__('RouterPwn')
        self.routers = {}
        self.skip_opts = True

    def load(self):
        """Load router modules"""
        for router in routers.__all__:
            # relative to zarp.py
            mod = importlib.import_module('modules.parameter.routers.%s'
                                                                    % router)
            self.routers[router] = []
            for vuln in mod.__all__:
                path = "modules.parameter.routers.%s.%s" % (router, vuln)
                if util.check_dependency(path):
                    mod = getattr(importlib.import_module(path, 'routers'), vuln)
                    self.routers[router].append(mod)

    def initialize(self):
        """ Load router exploits; store {router:[vuln]}
        """
        self.load()
        while True:
            choice = util.print_menu([x for x in self.routers.keys()])
            if choice is 0:
                del(self.routers)
                break
            elif choice is -1 or choice > len(self.routers.keys()):
                pass
            else:
                router = self.routers[self.routers.keys()[choice - 1]]
                while True:
                    choice = util.print_menu([x().which for x in router])
                    if choice is 0:
                        break
                    elif choice is -1 or choice > len(router):
                        pass
                    else:
                        stream.initialize(router[choice - 1])
