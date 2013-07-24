from scapy.error import Scapy_Exception
from signal import SIGINT
from datetime import date, datetime
from commands import getoutput
from subprocess import Popen
from cmd import Cmd
from pwd import getpwnam
from colors import color
from inspect import getmodule
import scapy.arch
import config
import os
import socket
import fcntl
import struct

"""Utility class housing various functions in use
    throughout the zarp framework.
"""

buffered = None


def version():
    """Zarp version"""
    return "0.1.4"


def header():
    """Zarp header"""
    print color.GREEN + '\t ____   __   ____  ____'
    print '\t(__  ) / _\ (  _ \(  _ \''
    print '\t / _/ /    \ )   / ) __/'
    print '\t(____)\_/\_/(__\_)(__)' + color.END
    print "\t    {0}[Version {1}]{2}\t\t\t".format(color.YELLOW, version(),
                                                                    color.END)
    if config.get('debug'):
        print '\t      ' + color.BLUE + ' [DEBUGGING]' + color.END


def Error(msg):
    """Prints the given message and, if debugging is on,
       logs it.
    """
    print color.RED + '[-] %s' % (msg) + color.END
    if config.get('debug'):
        debug(msg)


def Msg(msg):
    """Prints a warning message"""
    print color.YELLOW + '[!] %s' % (msg) + color.END


def debug(msg):
    """If debugging is enabled, write the given string
       to the debug file
    """
    dbg = config.get('log')
    if config.get('debug') and not os.path.islink(dbg):
        with open(dbg, 'a+') as f:
            f.write(format('[%s] %s\n' % (timestamp(), msg)))


def get_input(msg):
    """ fetch user input and unify input prompts
    """
    tmp = None
    try:
        tmp = raw_input('[!] %s' % msg)
    except:
        tmp = None
    return tmp


def get_calling_mod(stack):
    """ Retrieve the calling function based on the call stack
    """
    form = stack[1]
    return getmodule(form[0]).__name__


def timestamp():
    """ Generate a formatted timestamp
    """
    return '%s %s' % (date.today().isoformat(),
                                        datetime.now().strftime('%I:%M%p'))


def getipbyhost(hostname):
    """ return the IP address for a hostname
    """
    return socket.gethostbyname(hostname)


def next_ip(ip):
    """Return the next IP address following the given IP address.
       It needs to be converted to an integer, then add 1,
       then converted back to an IP address
    """
    ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
    int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
    return int2ip(ip2int(ip) + 1)


def is_in_subnet(ip, mask):
    """Check if a given IP address is lies within the given netmask
       TRUE if 'ip' falls within 'mask'
       FALSE otherwise
    """
    ipaddr = int(''.join(['%02x' % int(x) for x in ip.split('.')]), 16)
    netstr, bits = mask.split('/')
    netaddr = int(''.join(['%02x' % int(x) for x in netstr.split('.')]), 16)
    mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
    return (ipaddr & mask) == (netaddr & mask)


def check_program(prog):
    """Check if program is installed and pathed properly"""
    tmp = init_app('which {0}'.format(prog))
    if len(tmp) > 0 and '/' in tmp:
        return True
    else:
        return False


def init_app(prog, output=True):
    """inititalize an application
       PROG is the full command with args
       OUTPUT true if output should be returned
       false if output should be dumped to null.  This will
       return a process handle and is meant for initializing
       background processes.  Use wisely.
    """
    # dump output to null
    if not output:
        try:
            null = open(os.devnull, 'w')
            proc = Popen(prog, stdout=null, stderr=null)
        except Exception, j:
            Error("Error initializing app: %s" % j)
            return False
        return proc
    # just grab output
    else:
        return getoutput(prog)


def kill_app(proc):
    """Kill a process"""
    try:
        os.kill(proc.pid, SIGINT)
    except Exception, j:
        Error("Error killing app: %s" % (j))
        return False
    return True


def get_monitor_adapter():
    """Try and automatically detect which adapter is in monitor mode.
       NONE if there are none.
    """
    tmp = init_app('iwconfig', True)
    for line in tmp.split('\n'):
        if line.startswith(' '):
            continue
        elif len(line.split(' ')[0]) > 1:
            if 'Mode:Monitor' in line:
                return line.split(' ')[0]
    return None


def enable_monitor(channel=None):
    """Enable monitor mode on the wireless adapter
       CHANNEL is the channel to monitor on.
    """
    tmp = init_app('iwconfig', True)
    iface = None
    for line in tmp.split('\n'):
        if line.startswith('wlan'):
            try:
                iface = line.split(' ')[0]
                if channel is None:
                    tmp = getoutput('airmon-ng start {0}'.format(iface))
                else:
                    tmp = getoutput('airmon-ng start {0} {1}'
                                                    .format(iface, channel))
                debug("started \'%s\' in monitor mode" % iface)
            except Exception, j:
                Error("Error enabling monitor mode: %s" % j)
            break
    return get_monitor_adapter()


def disable_monitor():
    """Kill the monitoring adapter"""
    try:
        adapt = get_monitor_adapter()
        if not adapt is None:
            tmp = getoutput('airmon-ng stop %s' % adapt)
            debug('killed monitor adapter %s' % adapt)
    except Exception, j:
        Error('error killing monitor adapter:%s' % j)


def verify_iface(iface):
    """Verify that the given interface exists
    """
    try:
        tmp = init_app('ifconfig', True)
        if not iface in tmp:
            return False
        return True
    except Exception:
        return False


def does_file_exist(fle):
    """Check if a local file exists.
    """
    try:
        with open(fle) as f:
            pass
    except IOError:
        return False
    return True


def get_local_ip(adapter):
    """ Return the IP address of an adapter.
        @param adapter is the adapter to fetch from.
        I do not know how portable this is yet.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', adapter[:15])
            )[20:24])
    except:
        addr = None
    return addr


def test_filter(net_filter):
    """Test a network filter to verify if its valid"""
    valid = False
    try:
        scapy.arch.attach_filter(None, net_filter)
    except Scapy_Exception:
        pass
    except:
        valid = True
    return valid


def get_layer_bytes(layer):
    """I havent found a neat way to pull RAW bytes out of Scapy packets,
       so I just wrote a small utility function for it.
    """
    arr = []
    layer = layer.encode('hex')
    for (f, s) in zip(layer[0::2], layer[1::2]):
        arr.append(f + s)
    return arr


def check_opts(choice):
    """ Parse up the user input and run whatever commands
        are needed.
    """
    if type(choice) is int:
        return choice
    elif 'info' in choice:
        Error('\'info\' not implemented yet.')
        choice = -1
    elif 'help' in choice:
        help()
        choice = -1
    elif 'set' in choice:
        opts = choice.split(' ')
        if opts[1] is None or opts[2] is None:
            return
        print '[!] Setting ' + color.YELLOW + '%s' % opts[1] + color.END + \
                        '-> ' + color.GREEN + '%s..' % opts[2] + color.END
        config.set(opts[1], opts[2])
        choice = -1
    elif 'opts' in choice:
        config.dump()
        choice = -1
    elif 'quit' in choice or 'exit' in choice:
        # hard quit
        os._exit(1)
    elif 'bg' in choice:
        background()
    return choice


def help():
    """ Dump a help menu with zarp options
    """
    print color.YELLOW + '\n  zarp options:' + color.END
    print '\thelp\t\t- This menu'
    print '\topts\t\t- Dump zarp current settings'
    print '\texit\t\t- Exit immediately'
    print '\tbg\t\t- Put zarp to background'
    print '\tset [key] [value]\t- Set key to value'
    print color.GREEN + '  @dronesec - zarp v%s\n' % (version()) + color.END


def get_run_usr():
    """ Fetch the user that launched zarp
    """
    if 'SUDO_USER' in os.environ:
        usr = os.environ['SUDO_USER']
    else:
        usr = init_app('who -m | awk \'{print $1;}\'')

    # verify the user exists
    try:
        getpwnam(usr)
    except:
        usr = None
    return usr


def background():
    """ Drops the user back into their shell environment.
        'exit' brings them back.
    """

    usr = get_run_usr()
    if usr is None:
        return

    Msg('\'exit\' when you\'re done..')
    shell = os.environ['SHELL'] if 'SHELL' in os.environ else '/bin/bash'
    if check_program(shell):
        os.system('su -c %s %s' % (shell, usr))
    else:
        os.system('su -c /bin/sh %s' % usr)


def print_menu(arr):
    global buffered
    """Main menu printer
       @param arr is the menu array to print.  Fetches input,
        parses and built-in command keywords, and returns the selected idx.
    """

    if not buffered is None:
        # buffered input, return
        if len(buffered) > 0:
            return buffered.pop(0)
        else:
            buffered = None

    tmp = Cmd()
    arr = ['\t[%d] %s' % (x + 1, arr[x]) for x in xrange(len(arr))]
    tmp.columnize(arr, 35)
    print '\n0) Back'
    try:
        choice = raw_input('> ')
        choice = check_opts(choice)

        # buffered input
        if choice > 1:
            choice = choice.split(' ')
            buffered = []
            for entry in choice[1:]:
                buffered.append(int(entry))
            choice = int(choice[0])
    except KeyboardInterrupt:
        choice = -1
    except Exception, e:
        debug(e)
        os.system('clear')
        choice = -1
    return choice
