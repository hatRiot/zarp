from module import ZarpModule


class Parameter(ZarpModule):
    """ Abstract parameter
    """
    def __init__(self, which):
        super(Parameter, self).__init__(which)