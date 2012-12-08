import util, logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

#
# Main configuration class; set through the 'set' command
#	set KEY VALUE
#
class Configuration:
	def __init__(self):
		self.opts = {
					'iface' : conf.iface,
					'debug' : util.isDebug
					}

CONFIG = None

# initialize config
def initialize():
	global CONFIG
	CONFIG = Configuration()

# dump settings
def dump():
	global CONFIG
	print '\t\033[33m##|SETTING|\033[0m\t\033[32m|VALUE|##\033[0m'
	for k, v in CONFIG.opts.iteritems():
		print '\t%-10s\t %-25s'%(k, v)
		print '\t-----\t\t ------'
	print '\n'

# set the key to value
def set(key, value):
	global CONFIG
	if key in CONFIG.opts:
		# sometimes we gotta do stuff with the key
		if key == 'iface':
			if not util.verify_iface(value):
				util.Error('\'%s\' is not a valid interface.'%(value))
				return
		elif key == 'debug':
		  	value = util.isDebug if evalBool(value) is None else evalBool(value)
		  	util.isDebug = value
		CONFIG.opts[key] = value
	else:
		util.Error('Key "%s" not found.  \'opts\' for options.'%(key))

# get a key
def get(key):
	if key in CONFIG.opts:
		return CONFIG.opts[key]

#
# Keep set/unsetting booleans consistent.
#
def evalBool(value):
	if value in ['True', 'true']:
		return True
	elif value in ['False', 'false']:
		return False
	return None