import gc
import re
import config
from copy import copy
from colors import color
from textwrap import dedent
from util import Msg, Error, debug, check_opts, eval_type
from collections import OrderedDict, namedtuple

"""
    Main data bus for interacting with the various modules.  Dumps information,
    initializes objects, and houses all of the objects necessary to
    create/get/dump/stop the sniffers/poisoners.
"""

# main struct; ordered dictionary
HOUSE = OrderedDict()

class FailedCheck(Exception):
    """ Used primarily for error checking and breaking safely out 
        of outer loops.
    """
    pass

def initialize(module):
    """ Initialize a module and load it into the global HOUSE
        variable.  MODULE should be an instance of the loaded
        module.
    """
    global HOUSE
    debug("Received module start for: %s" % (module.__name__))
    if not 'service' in HOUSE:
        # services will always be 0
        HOUSE['service'] = {}

    tmp_mod = module()
    # option management interface; i.e. if we need to
    # load into another menu
    if not tmp_mod.skip_opts:
        response = handle_opts(tmp_mod)
    else:
        response = True

    if response:
        if hasattr(tmp_mod, 'initialize_bg'):
            tmp = tmp_mod.initialize_bg()
        else:
            tmp = tmp_mod.initialize()
    else:
        return

    if tmp is not None and tmp is not False:
        if not tmp_mod.which in HOUSE:
            HOUSE[tmp_mod.which] = {}
        HOUSE[tmp_mod.which][tmp] = tmp_mod


def handle_opts(module):
    """ The user has selected a module, so we should parse out all the
        options for this particular module, set the config, and when
        requested, run it.  This is kinda messy, but works for now.
    """
    # fetch generic module options and module-specific options
    options = module.config
    Setting = ['', 'Option', 'Value', 'Type', 'Required'] 
    while True:
        # generate list of opts
        table = []
        for idx, opt in enumerate(options.keys()):
            tmp = []
            tmp.append(idx+1)
            tmp.append(options[opt].display)
            tmp.append(options[opt].getStr())
            tmp.append(options[opt].type)
            tmp.append(options[opt].required)
            table.append(tmp)
        if len(table) > 0:
            config.pptable([Setting] + table)
        else:
            Msg('\tModule has no options.')
        print color.B_YELLOW + '0' + color.B_GREEN + ') ' + color.B_WHITE + 'Back' + color.END

        # fetch command/option
        try:
            choice = raw_input('%s > ' % (color.B_WHITE + module.which + color.END))

            # first check global commands
            tmp = check_opts(choice)
            if tmp == -1:
                continue

            # check module commands
            if choice is "0":
                return False
            elif choice == "info":
                if module.info is None:
                    Msg("Module has no information available")
                    continue

                print '%s%s%s' % (color.GREEN,
                                 '-' * len(module.info.split('\n')[1].strip()),
                                  color.END),
                print dedent(module.info.rstrip())
                print '%s%s%s' % (color.GREEN,
                                  '-' * len(module.info.split('\n')[1].strip()),
                                  color.END)
            elif len(choice.split(' ')) > 1:
                choice = choice.split(' ')
                try:
                    if int(choice[0]) > len(table):
                        continue
                    elif int(choice[0]) is 0:
                        return False

                    key = options.keys()[int(choice[0])-1]

                    if choice[1] == 'o' and module.config[key].opts is not None:
                        Msg("Options: %s" % module.config[key].opts)
                        continue
                    elif choice[1] == 'o' and module.config[key].type == 'list':
                        Msg('%s' % module.config[key].value)
                        continue

                    # generate a temporary zoption
                    tmp = copy(module.config[key])
                    tmp.value = ' '.join(choice[1::])

                    # we've got a valid number, validate the type and set it
                    if not tmp.validate():
                        Error('Wrong type assigned.  Expected value of type "%s"'%
                                        options[key].type)
                    else:
                        module.config[key] = tmp

                except Exception, e:
                    Error('%s' % e) 
                    continue
            elif "r" in choice.lower() or "run" in choice.lower():
                # verify all required options are set
                for opt in options.keys():
                    if options[opt].required and options[opt].value is None:
                        Error('Option \'%s\' is required.'%opt)
                        raise FailedCheck
                return True
        except KeyboardInterrupt:
            return False
        except FailedCheck:
            continue
        except Exception, e:
            Error('%s' % e)


def dump_sessions():
    """Format and print the currently running modules.
    """
    global HOUSE

    print color.B_GREEN + '\n\t[' + color.B_YELLOW + 'Running sessions' + \
          color.B_GREEN + ']' + color.END
    if 'service' in HOUSE:
        # services first
        tmp = HOUSE['service']
        if len(tmp) > 0:
            print color.B_GREEN + '[' + color.B_YELLOW + '0' + color.B_GREEN + \
                    '] ' + color.B_YELLOW + 'Services' + color.END
        for (cnt, service) in enumerate(tmp):
            print color.B_GREEN + '\t[' + color.B_YELLOW + str(cnt) + color.B_GREEN + \
                  '] ' + color.B_WHITE + tmp[service].session_view() + color.END
            if tmp[service].log_data:
                print color.B_YELLOW + '\t--> ' + color.B_WHITE + 'Logging to ' + \
                      tmp[service].log_file.name + color.END

    for (cnt, key) in enumerate(HOUSE.keys()):
        if key is 'service':
            continue
        if len(HOUSE[key]) > 0:
            print color.B_GREEN + '\t[' + color.B_YELLOW + str(cnt) + color.B_GREEN + \
                  ']' + color.B_WHITE  + ' ' + key + color.END
        for (cnt, obj) in enumerate(HOUSE[key]):
            print color.B_GREEN + '\t[' + color.B_YELLOW + str(cnt) + color.B_GREEN + \
                  '] ' + color.B_WHITE + HOUSE[key][obj].session_view() + color.END
            if hasattr(HOUSE[key][obj], 'log_data'):
                if HOUSE[key][obj].log_data:
                    print color.B_YELLOW + '\t|--> ' + color.B_WHITE + 'Logging to ' + \
                          HOUSE[key][obj].log_file.name + color.END
    print '\n'


def dump_module_sessions(module):
    """Dump running sessions for a module.
       @param module is the module to dump.
    """
    global HOUSE
    if not module in HOUSE.keys():
        Error('Module \'%s\' not found.' % module)
        return
    else:
        mod = HOUSE[module]

    print color.B_YELLOW + '[' + color.B_RED  + '!' + color.B_YELLOW + '] ' + \
          color.B_WHITE + module
    for (cnt, obj) in enumerate(mod.keys()):
        print color.B_GREEN + '\t[' + color.B_YELLOW + str(cnt) + color.B_GREEN + '] ' + \
              color.B_WHITE + str(obj)


def get_session_count():
    """ Return a count of the number of running sessions
    """
    global HOUSE
    cnt = 0
    if len(HOUSE.keys()) > 0:
        for key in HOUSE.keys():
            for entry in HOUSE[key]:
                if HOUSE[key][entry].running:
                    cnt += 1
    return cnt


def stop_session(module, number):
    """ Stop a specific session; calls the respective module's
         shutdown() method.
        @param module is the module number
        @param number is the session number
    """
    global HOUSE

    if module == 'all' and number == -1:
        # kill all
        for key in HOUSE.keys():
            for entry in HOUSE[key]:
                HOUSE[key][entry].shutdown()
    else:
        (mod, mod_inst) = get_mod_num(module, number)
        if not mod is None and not mod_inst is None:
            HOUSE[mod][mod_inst].shutdown()
            del(HOUSE[mod][mod_inst])
            if len(HOUSE[mod].keys()) is 0:
                del(HOUSE[mod])
        else:
            return
    gc.collect()


def view_session(module, number):
    """Initializes a module's view
        @param module is the module number
        @param number is the session number
    """
    global HOUSE

    mod = get_module(module, number)
    if hasattr(mod, 'view'):
        mod.view()


def toggle_log(module, number, file_loc=None, toggle=False):
    """Toggle the logger of a module
       @param module is the module number
       @param number is the session number
       @param file_loc is a string containing the file path
       @param toggle is True to turn on logging or False to turn off
    """
    (mod, mod_inst) = get_mod_num(module, number)
    if not mod is None and not mod_inst is None and hasattr(HOUSE[mod][mod_inst], 'log'):
        if toggle:
            # enable
            HOUSE[mod][mod_inst].log(True, file_loc)
        else:
            # disable
            HOUSE[mod][mod_inst].log(False)
    else:
        Error('Module does not have a logger or doesn\'t exist.')


def get_session_input():
    """ Helper for obtaining module and session numbers
    """
    try:
        display = color.B_GREEN + '[' + color.B_YELLOW + 'module' + color.B_GREEN + \
                  '] [' + color.B_YELLOW + 'number' + color.B_GREEN + ']' + \
                  color.B_WHITE + '> '
        tmp = raw_input(display)
        (module, number) = tmp.split(' ')
        if not module is None and not number is None:
            return (int(module), int(number))
    except Exception:
        Error('Must specify [module] followed by [number]\n')
        return (None, None)


def get_module(module, number):
    """ Retrieve an instance of a running session
        @param module is the module number
        @param number is the session number
    """
    (mod, mod_inst) = get_mod_num(module, number)
    if not mod is None and not mod_inst is None:
        return HOUSE[mod][mod_inst]
    return None


def get_mod_num(module, number):
    """Fetch the module and number instances given their
       indexes.
       @param module is the module index
       @param number is the module session index
    """
    if len(HOUSE.keys()) > module:
        mod = HOUSE.keys()[module]
        if len(HOUSE[mod].keys()) > number:
            mod_instance = HOUSE[mod].keys()[number]
            return (mod, mod_instance)
    return (None, None)
