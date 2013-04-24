import gc
from util import Error, Msg, debug
from collections import OrderedDict

#
# Main data bus for interacting with the various modules.  Dumps information, initializes objects,
# and houses all of the objects necessary to create/get/dump/stop the sniffers/poisoners.
#
# All around boss.
#

# main struct; ordered dictionary
HOUSE = OrderedDict()

def initialize(module, TYPE):
	""" Initialize a module and load it into the global HOUSE
		variable.  TYPE should be one of the corresponding strings
		from 'zarp'.  MODULE should be an instance of the loaded
		module.
	"""
	global HOUSE
	debug("Received module start for: %s"%(module.__name__))
	if not 'service' in HOUSE:
		# services will always be 0
		HOUSE['service'] = {}

	tmp_mod = module()
	if TYPE is 'POISON': 
		if not tmp_mod.which in HOUSE:
			HOUSE[tmp_mod.which] = {}
		to_ip = tmp_mod.initialize()
		if not to_ip is None:
			debug('Storing session for %s'%to_ip)
			HOUSE[tmp_mod.which][to_ip] = tmp_mod
	elif TYPE is 'SNIFFER':
		if not tmp_mod.which in HOUSE:
			HOUSE[tmp_mod.which] = {}
		to_ip = tmp_mod.initialize()
		if not to_ip is None:
			debug('Storing sniffer session for %s'%to_ip)
			HOUSE[tmp_mod.which][to_ip] = tmp_mod
	elif TYPE is 'DOS':
		# if you want the DoS module stored, return a key
		# from your module.
		tmp = tmp_mod.initialize()
		if tmp is not None:
			if not tmp_mod.which in HOUSE:
				HOUSE[tmp_mod.which] = {}
			HOUSE[tmp_mod.which][tmp] = tmp_mod
	elif TYPE is 'SERVICE':
		if tmp_mod.which in HOUSE['service']:
			Error('\'%s\' is already running.'%tmp_mod.which)
		else:
			if tmp_mod.initialize_bg():
				HOUSE['service'][tmp_mod.which] = tmp_mod
	elif TYPE is 'SCANNER':
		tmp = tmp_mod.initialize()
		if tmp is not None:
			if not tmp_mod.which in HOUSE:
				HOUSE[tmp_mod.which] = {}
			HOUSE[tmp_mod.which][tmp] = tmp_mod
#		tmp_mod.initialize()
	elif TYPE is 'PARAMETER':
		tmp_mod.initialize()

def dump_sessions():
	"""Format and print the currently running modules.
	"""
	global HOUSE
	print '\n\t[Running sessions]'

	if 'service' in HOUSE:
		# services first
		tmp = HOUSE['service']
		if len(tmp) > 0: print '[0] Services'
		for (cnt,service) in enumerate(tmp):
			print '\t\033[32m[%d] %s\033[0m'%(cnt,tmp[service].session_view())
			if tmp[service].log_data:
				print '\t--> \033[32mLogging to %s\033[0m'%(tmp[service].log_file.name)
	
	for (cnt,key) in enumerate(HOUSE.keys()):
		if key is 'service':
			continue
		if len(HOUSE[key]) > 0: print '[%d] %s'%(cnt, key)
		for (cnt,obj) in enumerate(HOUSE[key]):
			print '\t\033[32m[%d] %s\033[0m'%(cnt, HOUSE[key][obj].session_view())
			if hasattr(HOUSE[key][obj], 'log_data'):
				if HOUSE[key][obj].log_data:
					print '\t|--> Logging to ', HOUSE[key][obj].log_file.name
	print '\n'

def dump_module_sessions(module):
	"""Dump running sessions for a module.
	   @param module is the module to dump.
	"""
	global HOUSE 
	if not module in HOUSE.keys(): 
		Error('Module \'%s\' not found.'%module)
		return
	else:
		mod = HOUSE[module] 
	
	print '[!] %s'%module
	for (cnt,obj) in enumerate(mod.keys()):
		print '\t[%d] %s'%(cnt, obj)

def get_session_count():
	""" Return a count of the number of running sessions
	"""
	global HOUSE
	tmp = 0
	if len(HOUSE.keys()) > 0:
		for key in HOUSE.keys():
			tmp += len(HOUSE[key])
	return tmp

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
		Msg('[enter] when finished')
		mod.view()

def toggle_log(module, number, file_loc, toggle):
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
		tmp = raw_input('[module] [number]> ')
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

def view_info (module):
	""" Obtains help information for a module
		@param module is the module number
	"""
	print 'Received info start for ', module
	pass	
