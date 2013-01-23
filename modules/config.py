import util, logging, sys
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from collections import namedtuple

#
# Main configuration class; set through the 'set' command
#	set KEY VALUE
#
class Configuration:
	def __init__(self):
		self.opts = {
					'iface'  : conf.iface,
					'debug'  : util.isDebug,
					'ip_addr': util.get_local_ip(conf.iface)
					}

CONFIG = None

# initialize config
def initialize():
	global CONFIG
	CONFIG = Configuration()

# dump settings
def dump():
	global CONFIG

	# format the table data
	Setting = namedtuple('Setting', ['Key', 'Value']) 
	table = []
	for i in CONFIG.opts.keys():
		data = Setting(i, CONFIG.opts[i])
		table.append(data)
	# pass it to be printed
	pptable(table)

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
	if value in ['True', 'true', '1']:
		return True
	elif value in ['False', 'false', '0']:
		return False
	return None

#
# Print a formatted table given the sequence
# of tuples
#
def pptable(rows):
	if len(rows) > 1:
		headers = rows[0]._fields
		lens = []
		for i in range(len(rows[0])):
			lens.append(len(max([x[i] for x in rows] + [headers[i]],
						key=lambda x:len(str(x)))))
		formats = []
		hformats = []
		for i in range(len(rows[0])):
			formats.append('%%%ds'%lens[i])
			hformats.append("%%-%ds" % lens[i])
		pattern = " | ".join(formats)
		hpattern = " | ".join(hformats)
		separator = "-+-".join(['-' * n for n in lens])
		print '\t\033[32m' + hpattern % tuple(headers) + '\033[0m'
		print '\t' + separator
		for line in rows:
			print '\t' + pattern % tuple(line)
		print '\t' + separator
	elif len(rows) == 1:
		row = rows[0]
		hwidth = len(max(row._fields,key=lambda x:len(x)))
		for i in range(len(row)):
			print "%*s = %s" % (hwidth, row._fields[i],row[i])
