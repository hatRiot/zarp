#! /usr/local/bin/python

from os import getcwd, getuid
from sys import path, argv, exit
path.insert(0, getcwd() + '/modules/')
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
			mod = getattr(importlib.import_module('modules.dos.%s'%module, 'modules.dos'),module)
			self.dos.append(mod)
			self.total += 1
		for module in modules.poison.__all__:
			mod = getattr(importlib.import_module('modules.poison.%s'%module, 'modules.poison'),module)
			self.poison.append(mod)
			self.total += 1
		for module in modules.scanner.__all__:
			mod = getattr(importlib.import_module('modules.scanner.%s'%module, 'modules.scanner'),module)
			self.scanner.append(mod)
			self.total += 1
		for module in modules.services.__all__:
			mod = getattr(importlib.import_module('modules.services.%s'%module, 'modules.services'),module)
			self.services.append(mod)
			self.total += 1
		for module in modules.sniffer.__all__:
			mod = getattr(importlib.import_module('modules.sniffer.%s'%module, 'modules.sniffer'),module)
			self.sniffers.append(mod)
			self.total += 1
		for module in modules.parameter.__all__:
			mod = getattr(importlib.import_module('modules.parameter.%s'%module, 'modules.parameter'),module)
			self.parameter.append(mod)
			self.total += 1
	
def main():
	""" Zarp entry point
	"""

	# handle command line options first
	if len(argv) > 1:
		parse_cmd.parse(argv)
	
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
				choice = print_menu([x().which for x in loader.poison])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.poison):
					continue
				else:
					stream.initialize(loader.poison[choice-1], 'POISON')
		elif choice == 2:
			while True:
				choice = print_menu([x().which for x in loader.dos])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.dos):
					continue
				else:
					stream.initialize(loader.dos[choice-1], 'DOS')
		elif choice == 3:
			while True:
				choice = print_menu([x().which for x in loader.sniffers])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.sniffers):
					continue
				else:
					stream.initialize(loader.sniffers[choice-1], 'SNIFFER')	
		elif choice == 4:
			while True:
				choice = print_menu([x().which for x in loader.scanner])
				if choice == 0:
					break
				elif choice == -1:
					pass	
				elif choice > len(loader.scanner):
					continue
				else:
					stream.initialize(loader.scanner[choice-1], 'SCANNER')
		elif choice == 5:
			while True:
				choice = print_menu([x().which for x in loader.parameter])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.parameter):
					continue
				else:
					stream.initialize(loader.parameter[choice-1], 'PARAMETER')
		elif choice == 6:
			while True:
				choice = print_menu([x().which for x in loader.services])
				if choice == 0:
					break
				elif choice == -1:
					pass
				elif choice > len(loader.services):
					continue
				else:
					stream.initialize(loader.services[choice-1], 'SERVICE')
		elif choice == 7:
			session_manager.menu()
		elif choice == -1:
			pass

# Application entry; dependency checks, etc.
if __name__=="__main__":
	# perm check
	if int(getuid()) > 0:
		Error('Please run as root.')
		exit(1)
	# check for forwarding
	if not getoutput('cat /proc/sys/net/ipv4/ip_forward') == '1':
		Msg('IPv4 forwarding disabled.  Enabling..')
		tmp = getoutput('sudo sh -c \'echo "1" > /proc/sys/net/ipv4/ip_forward\'')	
		if len(tmp) > 0:
			Error('Error enabling IPv4 forwarding.')
			exit(1)
	# load local scapy lib
	path[:0] = [str(getcwd()) + '/scapy'] 
	main()
