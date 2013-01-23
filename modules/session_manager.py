import string
import stream, util
from os import system,path

#
# Module provides the front end for interacting with sessions
#

session_menu = [ 'Stop session', 'View session', 'Start session logger',
			 	 'Stop session logger' ]

#
# Driver for session management
#
def menu():
	while True:
		stream.dump_sessions()
		choice = util.print_menu(session_menu)

		if choice == 0:
			break
		elif choice == 1:
			module, number = get_session_input()
			if not module is None:
				stream.stop_session(string.lower(module), int(number))
			else:
				return
		elif choice == 2:
		  	module, number = get_session_input()
		  	if not module is None:
				stream.view_session(string.lower(module), int(number))
			else:
				return
		elif choice == 3:
			print '[!] Enter file to log to: '
			file_path = raw_input('> ')
			if file_path is None:
				return
			if util.does_file_exist(file_path) or path.islink(file_path):
				util.Error('File already exists.')
				return
			util.Msg('Module must be a sniffer or valid logging module.')
			module = None
			(module, number) = get_session_input()
			try:
				if not module is None:
					tmp = raw_input('[!] Log output from %s session %s to %s.  Is this correct? '%
																	(module,number,file_path))
				else:
					return
			except Exception, j:
				util.Error('Error logging to given file')
				return
			if 'n' in tmp.lower(): 
				return
			stream.start_log_session(module, int(number), file_path)
		elif choice == 4:
			(module, number) = get_session_input()
			if not module is None:
				stream.stop_log_session(module, int(number))
		else:
		  system('clear')

#
# internal for input reception
#
def get_session_input():
	try:
		tmp = raw_input('[module] [number]> ')
		(module, number) = tmp.split(' ')
		if not module is None and not number is None:
			return (module, number)
	except Exception: 
		util.Error('Must specify [module] followed by [number]\n')
		return (None, None)
