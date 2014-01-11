import util
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from collections import namedtuple
from colors import color
from sys import stdout

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
    table = [['Key', 'Value']]
    for i in CONFIG.opts.keys():
        table.append([i, str(CONFIG.opts[i]['value'])])
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
                set('iface',value)
                set('ip_addr', new_ip)
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
    if CONFIG:
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
        @param rows is a list of lists, first row assumed to be the header 
    """

    if len(rows) <= 0:
        return

    # Convert items to strings
    new_rows = []
    for i in rows:
        new_rows.append([str(r) for r in i])
    rows = new_rows

    # Add square brackets to numbers in left row
    for i in rows:
        try:
            if int(i[0]):
                i[0] = "[" + i[0] + "]"
        except:
            pass

    # Determine max length of columns
    lens = []
    headers = rows[0]
    for i in range(len(rows[0])):
        lens.append(len(str(max([x[i] for x in rows] + [headers[i]],
            key = lambda x: len(str(x))))))

    # Add spacing
    repack = []
    for row in rows:
        new_row = []
        for size,data in zip(lens,row):
            data = str(data)
            if len(data) < size:
                new_row.append(data + ((size - len(data)) * " "))
            else:
                new_row.append(data)
        repack.append(new_row)

    # Add color
    required_flag = False
    first_line = True
    if "Required" in repack[0]: required_flag = True
    added_colors = []
    for row in repack:
        new_line = []
        for i in row:
            if first_line:
                new_line.append(color.B_YELLOW + i + color.END)
            else:
                if required_flag and ("True" in i or "False" in i):
                    if "False" in i:
                        new_line.append(color.B_WHITE + i + color.END)
                    else:
                        new_line.append(color.B_CYAN + i + color.END)
                elif '[' in i or ']' in i:
                    i = i.replace('[', color.B_GREEN + '[' + color.B_YELLOW)
                    i = i.replace(']', color.B_GREEN + ']' + color.B_WHITE)
                    i = i + color.END
                    new_line.append(i)
                else:
                    new_line.append(color.B_WHITE + i + color.END)
        first_line = False
        added_colors.append(new_line)

    # Create spacing string
    space_string = '+-'
    for i in lens:
        space_string = space_string + ("-" * i) + "-+-"
    space_string = '\t' + space_string

    # Display glorious table
    print space_string
    for row in added_colors:
        first = True
        for i in row:
            if first is True:
                sys.stdout.write("\t| " + str(i))
                first = False
            else:
                sys.stdout.write(" | " + str(i))
        print ' | '
        print space_string
