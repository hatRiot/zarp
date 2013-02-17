#! /usr/local/bin/python
import os
import sys
sys.path.insert(0, os.getcwd() + '/modules/')
from util import get_subclass,print_menu, header, Error, Msg, debug
from commands import getoutput
import stream
import session_manager
import parse_cmd
import config
# module loading
import importlib
import modules.dos
import modules.poison
import modules.scanner
import modules.services
import modules.sniffer
import modules.parameter

class LoadedModules:
	""" Load modules
	"""
	def __init__(self):
		self.total      = 0
		self.poison     = []
		self.dos        = []
		self.sniffers   = []
		self.services   = []
		self.scanner    = []
		self.parameter  = []

	def load(self):
		for module in modules.dos.__all__:
			mod = importlib.import_module('modules.dos.%s'%module, 'modules.dos')
			self.dos.append(mod)
			self.total += 1
		for module in modules.poison.__all__:
			mod = importlib.import_module('modules.poison.%s'%module, 'modules.poison')
			self.poison.append(mod)
			self.total += 1
		for module in modules.scanner.__all__:
			mod = importlib.import_module('modules.scanner.%s'%module, 'modules.scanner')
			self.scanner.append(mod)
			self.total += 1
		for module in modules.services.__all__:
			mod = importlib.import_module('modules.services.%s'%module, 'modules.services')
			self.services.append(mod)
			self.total += 1
		for module in modules.sniffer.__all__:
			mod = importlib.import_module('modules.sniffer.%s'%module, 'modules.sniffer')
			self.sniffers.append(mod)
			self.total += 1
		for module in modules.parameter.__all__:
			mod = importlib.import_module('modules.parameter.%s'%module, 'modules.parameter')
			self.parameter.append(mod)
			self.total += 1
	
def main():
	""" Zarp entry point
	"""

	# handle command line options first
	if len(sys.argv) > 1:
		parse_cmd.parse(sys.argv)
	
	# set up configuration 
	config.initialize()

	# menus
	main_menu =    [ 'Poisoners', 'DoS Attacks', 'Sniffers', 'Scanners',
				     'Parameter','Services','Sessions']
	
	# load modules
	loader = LoadedModules()
	loader.load()
	Msg('Loaded %d modules.'%loader.total)
	
	running = True
	choice = -1
	while running:
		header()
		choice = print_menu(main_menu)		
		if choice == 0:
			# check if they've got running sessions! 
			cnt = stream.get_session_count()
			if cnt > 0:
				Msg('You have %d sessions running.  Are you sure?'%cnt)
				choice = raw_input('> ')
				if 'y' in choice.lower(): 
					Msg('Shutting all sessions down...')
					stream.stop_session('all', -1)
					running = False	
			else:
				debug("Exiting with session count: %d"%(cnt))
				Msg("Exiting...")
				running = False
		elif choice == 1:
			while True:
				choice = print_menu([x.__name__ for x in loader.poison])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.poison):
					continue
				else:
					sclass = get_subclass(loader.poison[choice-1], modules.poison.poison.Poison)
					stream.initialize(sclass, 'POISON')
		elif choice == 2:
			while True:
				choice = print_menu([x.__name__ for x in loader.dos])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.dos):
					continue
				else:
					sclass = get_subclass(loader.dos[choice-1], modules.dos.dos.DoS)
					stream.initialize(sclass, 'DOS')
		elif choice == 3:
			while True:
				choice = print_menu([x.__name__ for x in loader.sniffers])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.sniffers):
					continue
				else:
					sclass = get_subclass(loader.sniffers[choice-1], modules.sniffer.sniffer.Sniffer)
					stream.initialize(sclass, 'SNIFFER')	
		elif choice == 4:
			while True:
				choice = print_menu([x.__name__ for x in loader.scanner])
				if choice == 0:
					break
				elif choice == -1:
					pass	
				elif choice > len(loader.scanner):
					continue
				else:
					sclass = get_subclass(loader.scanner[choice-1],modules.scanner.scanner.Scanner)
					stream.initialize(sclass, 'SCANNER')
		elif choice == 5:
			while True:
				choice = print_menu([x.__name__ for x in loader.parameter])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.parameter):
					continue
				else:
					sclass = get_subclass(loader.parameter[choice-1],modules.parameter.parameter.Parameter)
					stream.initialize(sclass, 'PARAMETER')
		elif choice == 6:
			while True:
				choice = print_menu([x.__name__ for x in loader.services])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.services):
					continue
				else:
					sclass = get_subclass(loader.services[choice-1], modules.services.service.Service)
					stream.initialize(sclass, 'SERVICE')
		elif choice == 7:
			session_manager.menu()
		elif choice == -1:
			pass

# Application entry; dependency checks, etc.
if __name__=="__main__":
	# perm check
	if int(os.getuid()) > 0:
		Error('Please run as root.')
		sys.exit(1)
	# check for forwarding
	if not getoutput('cat /proc/sys/net/ipv4/ip_forward') == '1':
		Msg('IPv4 forwarding disabled.  Enabling..')
		tmp = getoutput('sudo sh -c \'echo "1" > /proc/sys/net/ipv4/ip_forward\'')	
		if len(tmp) > 0:
			Error('Error enabling IPv4 forwarding.')
			sys.exit(1)
	# load local scapy lib
	sys.path[:0] = [str(os.getcwd()) + '/scapy'] 
	main()
