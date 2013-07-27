import util
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from collections import namedtuple
from colors import color


class Configuration:
    """ Main configuration; just hold options
    """
    def __init__(self):
        self.opts = {
                    'iface'  : {'value':conf.iface, 'type':'str'},
                    'debug'  : {'value':False,      'type':'bool'},
                    'ip_addr': {'value':util.get_local_ip(conf.iface),
                                'type':'ip'},
                    'log'    : {'value':'zarp_debug.log', 'type':'str'}
                    }

        self._opts = {
                    'db_ip'  : {'value':'localhost','type':'ip'},
                    'db_port': {'value':None, 'type':'int'},
                    'db_usr' : {'value':None, 'type':'str'},
                    'db_pw'  : {'value':None, 'type':'str'},
                    'db_con' : {'value':None, 'type':'str'}
                    }
CONFIG = None


def initialize():
    """ Initializes local config object
    """
    global CONFIG
    CONFIG = Configuration()
    parse_config()


def dump():
    """ Dumps out the current settings in a pretty
        table
    """
    global CONFIG

    # format the table data
    Setting = namedtuple('Setting', ['Key', 'Value'])
    table = []
    for i in CONFIG.opts.keys():
        data = Setting(i, str(CONFIG.opts[i]['value']))
        table.append(data)
    pptable(table)


def set(key, value):
    """ Sets the key to the vale
        @param key is the configuration key
        @param value is what to set it to
    """
    global CONFIG
    if key in CONFIG.opts:
        # sometimes we gotta do stuff with the key
        if key == 'iface':
            if not util.verify_iface(value):
                util.Error('\'%s\' is not a valid interface.' % (value))
                return

            # valid iface, set new ipconfig
            new_ip = util.get_local_ip(value)
            if new_ip is not None:
                set('iface', new_ip)
        else:
            res = util.eval_type(value, CONFIG.opts[key]['type'])
            if res[0]:
                CONFIG.opts[key]['value'] = res[1]
    elif key in CONFIG._opts:
        # options not available in CLI
        res = util.eval_type(value, CONFIG._opts[key]['type'])
        if res[0]:
            CONFIG._opts[key]['value'] = res[1]
        else:
            return
    else:
        util.Error('Key "%s" not found.  \'opts\' for options.' % (key))


def get(key):
    """Fetch a config value
       @param key is the config key value
    """
    if key in CONFIG.opts:
        return CONFIG.opts[key]['value']
    elif key in CONFIG._opts:
        return CONFIG._opts[key]['value']


def parse_config():
    """ Parse the zarp config file
    """
    global CONFIG
    try:
        for line in open('config/zarp.conf', 'r').readlines():
            if line[0] == '#' or '=' not in line or len(line) < 1:
                continue

            vals = [k.strip().replace('\n', '') for k in line.split('=')]
            if len(vals) == 2:
                set(vals[0], vals[1])
    except Exception, e:
        util.Error(e)


def pptable(rows):
    """ Pretty print a table
        @param rows is a sequence of tuples
    """
    headers = rows[0]._fields
    lens = []
    for i in range(len(rows[0])):
        lens.append(len(str(max([x[i] for x in rows] + [headers[i]],
                    key=lambda x: len(str(x))))))
    formats = []
    hformats = []
    for i in range(len(rows[0])):
        formats.append('%%%ds' % lens[i])
        hformats.append("%%-%ds" % lens[i])
    pattern = " | ".join(formats)
    hpattern = " | ".join(hformats)
    separator = "-+-".join(['-' * n for n in lens])
    print color.GREEN + '\t' + hpattern % tuple(headers) + color.END
    print '\t' + separator
    for line in rows:
        print '\t' + pattern % tuple(line)
    print '\t' + separator