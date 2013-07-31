from util import eval_type

class Zoption:
    """ generic option class for managing and validating
        zarp options.
    """
    def __init__(self, value = None, type = None, required = False, 
                       display = None, opts = None):
        self.value = value
        self.type = type
        self.required = required
        self.display = display
        self.opts    = opts

    def getStr(self):
        """ Some objects don't have a __str__ method (regex),
            so we'll need to return the string representation
            of the object.
        """
        if self.value is None:
            return None
        elif self.type == "regex":
            return self.value.pattern
        else:
            return str(self.value)

    def validate(self):
        """ Validates the object's value to ensure it conforms
            to whatever type the object dictates.
        """
        rvals = eval_type(self.value, self.type)
        if rvals[0]:
            self.value = rvals[1]
            return True
        else:
            return False