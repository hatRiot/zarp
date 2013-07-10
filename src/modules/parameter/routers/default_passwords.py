""" Aggregation of default passwords, organized by brand.  Only
    brands with exploits in zarp are present.
"""


def default_list(brand):
    """ Return a list of potential or default username/password
        combinations for a router.  This is more refined than a
        brute force attempt with a fat wordlist.
    """
    brand = globals().get(brand)()
    if not brand:
        return None

    base = general()

    # uniquely combine lists
    base['username'] = list(set(base['username'] + brand['username']))
    base['password'] = list(set(base['password'] + brand['password']))
    return base


def general():
    """ standard username/password combinations that could be
        applicable to any device.  Each brand should return the
        union of the general set and their specific subset.
    """
    return {'username': ['', 'admin', 'administrator'],
            'password': ['', 'admin', 'administrator', 'password', '1234']
            }


#
# Brand-specific usernames/passwords
#
def cisco():
    return {'username': ['Cisco', 'cisco', 'Administrator', 'root'],
            'password': ['Cisco', 'cisco', 'Administrator', '_Cisco', 'letmein']
            }


def asus():
    return {'username': [],
            'password': []
            }


def rosewill():
    return {'username': [],
            'password': ['guest'],
            }


def dlink():
    return {'username': [],
            'password': ['public']
            }


def linksys():
    return {'username': [],
            'password': ['epicrouter']
            }


def netgear():
    return {'username': [],
            'password': ['netgear1', 'setup', 'Administrator']
            }
