import util
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from collections import namedtuple
from colors import color

class Configuration:
	""" Main configuration; just holds options
	"""
	def __init__(self):
		self.opts = {
					'iface'  : {'value':conf.iface, 'type':str},
					'debug'  : {'value':False,      'type':bool},
					'ip_addr': {'value':util.get_local_ip(conf.iface),'type':str},
					'log'    : {'value':'zarp_debug.log', 'type':str}
					}

CONFIG = None

def initialize():
	""" Initializes local config object
	"""
	global CONFIG
	CONFIG = Configuration()

def dump():
	""" Dumps out the current settings in a pretty
		table
	"""
	global CONFIG

	# format the table data
	Setting = namedtuple('Setting', ['Key', 'Value']) 
	table = []
	for i in CONFIG.opts.keys():
		data = Setting(i, str(CONFIG.opts[i]['value']))
		table.append(data)
	pptable(table)

def set(key, value):
	""" Sets the key to the vale
		@param key is the configuration key
		@param value is what to set it to
	"""
	global CONFIG
	if key in CONFIG.opts:
		# sometimes we gotta do stuff with the key
		if key == 'iface':
			if not util.verify_iface(value):
				util.Error('\'%s\' is not a valid interface.'%(value))
				return
		if CONFIG.opts[key]['type'] is bool:
			if evalBool(value) is not None: value = evalBool(value)
			else: return
		CONFIG.opts[key]['value'] = value
	else:
		util.Error('Key "%s" not found.  \'opts\' for options.'%(key))

def get(key):
	"""Fetch a config value
	   @param key is the config key value
	"""
	if key in CONFIG.opts:
		return CONFIG.opts[key]['value']

def evalBool(value):
	"""User input is evil
	   @param value is the value to evaluate
	""" 
	if value in ['True', 'true', '1']:
		return True
	elif value in ['False', 'false', '0']:
		return False
	return None

def pptable(rows):
	""" Pretty print a table
		@param rows is a sequence of tuples
	"""
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
		print color.GREEN + '\t' + hpattern % tuple(headers) + color.END
		print '\t' + separator
		for line in rows:
			print '\t' + pattern % tuple(line)
		print '\t' + separator
	elif len(rows) == 1:
		row = rows[0]
		hwidth = len(max(row._fields,key=lambda x:len(x)))
		for i in range(len(row)):
			print "%*s = %s" % (hwidth, row._fields[i],row[i])
