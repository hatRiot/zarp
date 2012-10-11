import string
import util, stream
from os import system

#
# Module provides the front end for interacting with sessions
#

#
# Driver for session management
#
def menu():
	while True:
		stream.dump_sessions()
		print '\t[1] Stop session'
		print '\t[2] View session'
		print '\t[3] Start session logger'
		print '\t[4] Stop session logger'
		print '\n0) Back'
		try:
			choice = int(raw_input('> '))
		except Exception:
			system('clear')
			continue
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
			if util.does_file_exist(file_path):
				print '[-] File already exists.'
				return
			print '[!] Module must be a sniffer.'
			module = None
			(module, number) = get_session_input()
			try:
				if not module is None:
					tmp = raw_input('[!] Log output from %s session %s to %s.  Is this correct? '%
																	(module,number,file_path))
				else:
					return
			except Exception, j:
				print '[dbg] Exception: ',j
				return
			if tmp == 'n':
				return
			stream.start_log_session(module, int(number), file_path)
		elif choice == 4:
			(module, number) = get_session_input()
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
		print '[dbg] got: %s and %s'%(module, number)
		if not module is None and not number is None:
			return (module, number)
	except Exception: 
		print '[-] Error: Must specify [module] followed by [number]\n'
		return (None, None)
