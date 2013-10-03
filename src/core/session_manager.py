import stream
import util
from colors import color
from os import system
from os import path

#
# Module provides the front end for interacting with sessions
#

session_menu = ['Stop session', 'View session', 'Start session logger',
                  'Stop session logger']


def menu():
    """Driver for the session management menu
    """
    while True:
        stream.dump_sessions()
        choice = util.print_menu(session_menu)

        if choice == 0:
            break
        elif choice == 1:
            (module, number) = stream.get_session_input()
            if not module is None:
                stream.stop_session(module, number)
        elif choice == 2:
            (module, number) = stream.get_session_input()
            if not module is None:
                stream.view_session(module, number)
        elif choice == 3:
            try:
                display = color.B_YELLOW + '[' + color.B_GREEN + '!' + color.B_YELLOW + \
                          '] Enter file to log to' + color.B_WHITE + ' > ' + color.END
                file_path = raw_input(display)
                if file_path is None:
                    return
                if util.does_file_exist(file_path) or path.islink(file_path):
                    util.Error('File already exists.')
                    return
                (module, number) = stream.get_session_input()
                if not module is None:
                    display = color.B_YELLOW + '[' + color.B_GREEN + '!' + color.B_YELLOW + \
                              '] Log output from %s session %s to %s. Is this correct? '  + \
                              color.B_GREEN + '[' + color.B_YELLOW + 'Y' + color.B_GREEN + \
                              '/' + color.B_YELLOW + 'n' + color.B_GREEN + '] ' + \
                              color.B_WHITE + '> ' + color.END
                    tmp = raw_input(display % (module, number, file_path))
                    if 'n' in tmp.lower():
                        return
                    stream.toggle_log(module, number, file_path, True)
            except KeyboardInterrupt:
                return
            except Exception:
                util.Error('Error logging to given file')
                return
        elif choice == 4:
            (module, number) = stream.get_session_input()
            if not module is None:
                stream.toggle_log(module, number)
        elif choice == -1:
            pass
        else:
            system('clear')
