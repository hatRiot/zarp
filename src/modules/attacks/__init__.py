from os.path import basename, dirname, abspath
from glob import glob

__all__ = [i for i in (basename(f)[:-3] for f in glob(dirname(abspath(__file__))+"/*.py")) if i != "__init__" and i != "attack"]
__all__ = [v for v in __all__ if not v == "__init__"]
