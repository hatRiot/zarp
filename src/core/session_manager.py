import stream
import util
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
            print '[!] Enter file to log to: '
            file_path = raw_input('> ')
            if file_path is None:
                return
            if util.does_file_exist(file_path) or path.islink(file_path):
                util.Error('File already exists.')
                return
            util.Msg('Module must be a sniffer or valid logging module.')
            (module, number) = stream.get_session_input()
            try:
                if not module is None:
                    tmp = raw_input('[!] Log output from %s session %s to %s.'
                        'Is this correct? ' % (module, number, file_path))
                    if 'n' in tmp.lower():
                        return
                    stream.toggle_log(module, number, file_path, True)
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