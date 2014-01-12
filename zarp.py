#! /usr/bin/python

from os import getcwd, getuid, _exit
from os.path import exists
from sys import path, argv, exit, version, version_info
path.insert(0, getcwd() + '/src/')
path.insert(0, getcwd() + '/src/core/')
path.insert(0, getcwd() + '/src/modules/')
path.insert(0, getcwd() + '/src/lib/')
from commands import getoutput
# module loading
from src.modules import poison, dos, scanner, services
from src.modules import sniffer, parameter, attacks
import config
import database
from colors import color
import platform
import util

try:
    # load py2.7 stuff here so we can get to the depends check
    import parse_cmd
    import importlib
    import session_manager
    import stream
except:
    pass


class LoadedModules:
    """ Load modules
    """
    def __init__(self):
        self.total = 0
        self.poison = []
        self.dos = []
        self.sniffers = []
        self.services = []
        self.scanner = []
        self.parameter = []
        self.attacks = []

    def load(self):
        """ Load modules.  Verify the module loads successfully
            before loading it up into the module list; this prevents
            crashes related to unmet dependencies.
        """
        for module in poison.__all__:
            if util.check_dependency('src.modules.poison.%s' % module):
                mod = getattr(importlib.import_module(
                            'src.modules.poison.%s' % module, 'poison'), 
                            module)
                self.poison.append(mod)
                self.total += 1
        for module in dos.__all__:
            if util.check_dependency('src.modules.dos.%s' % module):
                mod = getattr(importlib.import_module(
                                'src.modules.dos.%s' % module, 'dos'), 
                                module)
                self.dos.append(mod)
                self.total += 1
        for module in scanner.__all__:
            if util.check_dependency('src.modules.scanner.%s' % module):
                mod = getattr(importlib.import_module(
                            'src.modules.scanner.%s' % module, 'scanner'), 
                            module)
                self.scanner.append(mod)
                self.total += 1
        for module in services.__all__:
            if util.check_dependency('src.modules.services.%s' % module):
                mod = getattr(importlib.import_module(
                            'src.modules.services.%s' % module, 'services'), 
                            module)
                self.services.append(mod)
                self.total += 1
        for module in sniffer.__all__:
            if util.check_dependency('src.modules.sniffer.%s' % module):
                mod = getattr(importlib.import_module(
                            'src.modules.sniffer.%s' % module, 'sniffer'), 
                            module)
                self.sniffers.append(mod)
                self.total += 1
        for module in parameter.__all__:
            if util.check_dependency('src.modules.parameter.%s' % module):
                mod = getattr(importlib.import_module(
                            'src.modules.parameter.%s' % module, 'parameter'), 
                            module)
                self.parameter.append(mod)
                self.total += 1
        for module in attacks.__all__:
            if util.check_dependency('src.modules.attacks.%s' % module):
                mod = getattr(importlib.import_module(
                            'src.modules.attacks.%s' % module, 'attacks'), 
                            module)
                self.attacks.append(mod)
                self.total += 1


def main():
    """ Zarp entry point
    """

    # set up configuration
    config.initialize()

    # set up database
    database.initialize()

    # load modules
    loader = LoadedModules()
    loader.load()
    util.Msg('Loaded %d modules.' % loader.total)

    # handle command line options first
    if len(argv) > 1:
        parse_cmd.parse(argv, loader)

    # menus
    main_menu = ['Poisoners', 'DoS Attacks', 'Sniffers', 'Scanners',
                     'Parameter', 'Services', 'Attacks', 'Sessions']

    running = True
    choice = -1
    while running:
        util.header()
        choice = util.print_menu(main_menu)
        if choice == 0:
            # check if they've got running sessions!
            cnt = stream.get_session_count()
            if cnt > 0:
                display = color.B_YELLOW + 'You have %d sessions running. ' + \
                          'Are you sure? ' + color.B_GREEN + '[' + color.B_YELLOW + \
                          'Y' + color.B_GREEN + '/' + color.B_YELLOW + 'n' + \
                          color.B_GREEN + '] ' + color.END
                choice = raw_input(display % cnt)
                if 'y' in choice.lower() or choice == '':
                    util.Msg('Shutting all sessions down...')
                    stream.stop_session('all', -1)
                    running = False

            else:
                util.debug("Exiting with session count: %d" % (cnt))
                util.Msg("Exiting...")
                running = False

            # remove zarp temporary directory
            util.init_app('rm -fr /tmp/.zarp/')
             
            # recheck that all sessions are down
            cnt = stream.get_session_count()
            if cnt <= 0:
               # some libs dont clean up their own threads, so
               # we need to hard quit those to avoid hanging; FIXME
               _exit(1)
        elif choice == 1:
            while True:
                choice = util.print_menu([x().which for x in loader.poison])
                if choice == 0:
                    break
                elif choice == -1:
                    pass
                elif choice > len(loader.poison):
                    continue
                else:
                    stream.initialize(loader.poison[choice - 1])
        elif choice == 2:
            while True:
                choice = util.print_menu([x().which for x in loader.dos])
                if choice == 0:
                    break
                elif choice == -1:
                    pass
                elif choice > len(loader.dos):
                    continue
                else:
                    stream.initialize(loader.dos[choice - 1])
        elif choice == 3:
            while True:
                choice = util.print_menu([x().which for x in loader.sniffers])
                if choice == 0:
                    break
                elif choice == -1:
                    pass
                elif choice > len(loader.sniffers):
                    continue
                else:
                    stream.initialize(loader.sniffers[choice - 1])
        elif choice == 4:
            while True:
                choice = util.print_menu([x().which for x in loader.scanner])
                if choice == 0:
                    break
                elif choice == -1:
                    pass
                elif choice > len(loader.scanner):
                    continue
                else:
                    stream.initialize(loader.scanner[choice - 1])
        elif choice == 5:
            while True:
                choice = util.print_menu([x().which for x in loader.parameter])
                if choice == 0:
                    break
                elif choice == -1:
                    pass
                elif choice > len(loader.parameter):
                    continue
                else:
                    stream.initialize(loader.parameter[choice - 1])
        elif choice == 6:
            while True:
                choice = util.print_menu([x().which for x in loader.services])
                if choice == 0:
                    break
                elif choice == -1:
                    pass
                elif choice > len(loader.services):
                    continue
                else:
                    stream.initialize(loader.services[choice - 1])
        elif choice == 7:
            while True:
                choice = util.print_menu([x().which for x in loader.attacks])
                if choice == 0:
                    break
                elif choice == -1:
                    pass
                elif choice > len(loader.attacks):
                    continue
                else:
                    stream.initialize(loader.attacks[choice - 1])
        elif choice == 8:
            session_manager.menu()
        elif choice == -1:
            pass

# Application entry; dependency checks, etc.
if __name__ == "__main__":
    # perm check
    if int(getuid()) > 0:
        util.Error('Please run as root.')
        _exit(1)

    # check python version
    if version_info[1] < 7:
        util.Error('zarp must be run with Python 2.7.x.  You are currently using %s'
        % version)
        _exit(1)

    # check for forwarding
    system = platform.system().lower()
    if system == 'darwin':
        if not getoutput('sysctl -n net.inet.ip.forwarding') == '1':
            util.Msg('IPv4 forwarding disabled. Enabling..')
            tmp = getoutput(
                    'sudo sh -c \'sysctl -w net.inet.ip.forwarding=1\'')
            if 'not permitted' in tmp:
                util.Error('Error enabling IPv4 forwarding.')
                exit(1)
    elif system == 'linux':
        if not getoutput('cat /proc/sys/net/ipv4/ip_forward') == '1':
            util.Msg('IPv4 forwarding disabled.  Enabling..')
            tmp = getoutput(
                    'sudo sh -c \'echo "1" > /proc/sys/net/ipv4/ip_forward\'')
            if len(tmp) > 0:
                util.Error('Error enabling IPv4 forwarding.')
                exit(1)
    else:
        util.Error('Unknown operating system. Cannot IPv4 forwarding.')
        exit(1)

    # create temporary directory for zarp to stash stuff
    if exists("/tmp/.zarp"):
        util.init_app("rm -fr /tmp/.zarp")
    util.init_app("mkdir /tmp/.zarp")

    main()
