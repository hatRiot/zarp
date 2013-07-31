import sys
import argparse
import util

from scapy.all import *
from scapy.error import Scapy_Exception


def parse(sysv, loader):
    """ Modules can set their own CLI options.  Right now we only
        load services and scanners, as these represent a majority of
        the 'typical' use case for something you want to pull off quickly.

        loader is a Loader object with all loaded modules.
    """
    parser = argparse.ArgumentParser(description=util.header())

    # add standard options
    parser.add_argument('-q', help='Generic network sniff', action='store',
                                                            dest='filter')
    parser.add_argument('--update', help='Update Zarp', action='store_true',
                                default=False, dest='update')

    service_group = parser.add_argument_group('Services')
    scanner_group = parser.add_argument_group('Scanners')

    # iterate through loaded modules and build the argument parser
    for service in loader.services:
        if hasattr(service, 'cli'):
            service().cli(service_group)

    for scanner in loader.scanner:
        if hasattr(scanner, 'cli'):
            scanner().cli(scanner_group)

    options = parser.parse_args()
    option_dict = options.__dict__

    # first handle standard options
    if options.filter:
        util.Msg("Sniffing with filter [%s]...(ctrl^c to exit)" %
                                                                options.filter)
        try:
            sniff(filter=options.filter, store=0, prn=lambda x: x.summary())
        except Exception:
            util.Msg("Exiting sniffer..")
        except Scapy_Exception as msg:
            util.Error(msg)
        sys.exit(1)
    elif options.update:
        update()
        sys.exit(1)

    # we can only launch one module at a time, so grab the first
    usr_mod = [x for x in option_dict.keys() if option_dict[x] is True][0]

    # see what it is
    if usr_mod in [x().which for x in loader.services]:
        module = [x for x in loader.services if x().which == usr_mod][0]
        util.Msg('Starting %s...' % module().which)
        mod = module()
        mod.dump_data = True
        mod.initialize()
    elif usr_mod in [x().which for x in loader.scanner]:
        module = [x for x in loader.scanner if x().which == usr_mod][0]
        module().initialize()
    sys.exit(1)


def update():
    """ Run update routine
    """
    if not util.does_file_exist('./.git/config'):
        util.Error('Not a git repo; please checkout from Github with \n\t'
                'git clone http://github.com/hatRiot/zarp.git\n to update.')
    else:
        util.Msg('Updating Zarp...')
        ret = util.init_app('git branch -a | grep \'* dev\'', True)
        if len(ret) > 3:
            util.Error('You appear to be on the dev branch.'
                        'Please switch off dev to update.')
            return

        ret = util.init_app('git pull git://github.com/hatRiot/zarp.git HEAD')
        if 'Already up-to-date' in ret:
            util.Msg('Zarp already up to date.')
        elif 'fatal' in ret:
            util.Error('Error updating Zarp: %s' % ret)
        else:
            from util import version
            util.Msg('Zarp updated to version %s' % (version()))
