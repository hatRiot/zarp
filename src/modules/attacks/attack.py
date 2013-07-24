from module import ZarpModule
import abc

class Attack(ZarpModule):
    """Abstract attack class"""
    __metaclass__ = abc.ABCMeta

    def __init__(self, which):
        super(Attack, self).__init__(which)