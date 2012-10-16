from signal import SIGINT
from datetime import date, datetime
from commands import getoutput
from subprocess import Popen
import os

#
# Class houses utility functions
#

isDebug = False
DEBUG_LOG = 'zarp_debug.log'

# zarp version
def version():
	return 0.03

# zarp header
def header():
	print "\t        [\033[31mZARP\033[0m]\t\t" #red
	print "\t    [\033[32mVersion %s\033[0m]\t\t\t"%(version()) #yellow

#
# Print the passed error message in red formatted text!
#
def Error(msg):
	print '\033[31m[-] %s'%(msg)
	if isDebug:
		debug(msg)	

#
# Print a warning/message in yellow formatted text!
#
def Msg(msg):
	print '\033[33m[!] %s'%(msg)

# if debugging, write to dbg file
def debug(msg):
	if isDebug and not os.path.islink(DEBUG_LOG):
		with open(DEBUG_LOG, 'a+') as f:
			f.write(format('[%s %s] %s'%(date.today().isoformat(), datetime.now().strftime("%I:%M%p"), msg)))

# return the next IP address following the given IP address.
# It needs to be converted to an integer, then add 1, then converted back to an IP address
def next_ip(ip):
	ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
	int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
	return int2ip(ip2int(ip) + 1)

# Check if a given IP address is lies within the given netmask
# TRUE if 'ip' falls within 'mask'
# FALSE otherwise
def is_in_subnet(ip, mask):
	ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.')]), 16)
	netstr,bits = net.split('/')
	netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.')]), 16)
	mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
	return (ipaddr & mask) == (netaddr & mask)	

# verify if an app is installed (and pathed) properly 
def check_program(prog):
	tmp = init_app('which {0}'.format(prog), True)
	if len(tmp) > len(prog) and '/' in tmp:
		return True
	else:
		return False

# initialize an application 
# PROG is the full command with args
# OUTPUT true if output should be returned
#		 false if output should be dumped to null.  This will
#		 return a process handle and is meant for initializing 
#		 background processes.  Use wisely.
def init_app(prog, output):
	# dump output to null
	if not output:
		try:
			null = open(os.devnull, 'w')
			proc = Popen(prog, stdout=null, stderr=null)
		except Exception,j:
			print '[dbg] error init: ', j
			return False
		return proc
	# just grab output
	else:
		return getoutput(prog)

#
# kill an application
#
def kill_app(proc):
	try:
		os.kill(proc.pid, SIGINT)
	except Exception, j:
		print '[dbg] error kill: ', j
		return False
	return True

#
# Try and automatically detect which adapter is in monitor mode
# NONE if there are none
#
def get_monitor_adapter():
	tmp = init_app('iwconfig', True)
	iface = None
	for line in tmp.split('\n'):	
		if line.startswith(' '):
			continue	
		elif len(line.split(' ')[0]) > 1:
			if 'Mode:Monitor' in line:
				return line.split(' ')[0]
	return None

#
# Enable monitor mode on the wireless adapter
#
def enable_monitor():
	tmp = init_app('iwconfig', True)
	iface = None
	for line in tmp.split('\n'):
		if line.startswith('wlan'):
			try:
				iface = line.split(' ')[0]
				tmp = getoutput('airmon-ng start {0}'.format(iface))
				print '[dbg] started \'%s\' in monitor mode'%iface
			except Exception, j:
				print 'error enabling monitor mode: ', j
			break
	return get_monitor_adapter()

#
# Kill the monitoring adapter
#
def disable_monitor():
	try:
		adapt = get_monitor_adapter()
		if not adapt is None:
			tmp = getoutput('airmon-ng stop %s'%adapt)
			print '[dbg] killed monitor adapter ', adapt 
	except Exception, j:
		print '[dbg] error killing monitor adapter: ', j

#
# check if a local file exists
# TRUE if it does, FALSE otherwise
#
def does_file_exist(fle):
	try:
		with open(fle) as f: pass
	except IOError:
		return False
	return True
#
# Helper for the interface.
# arr is a list of items for display
#
def print_menu(arr):
	i = 0
	while i < len(arr):
		# if there are more than 6 items in the list, add another column
		if len(arr) > 6 and i < len(arr)-1:
			print '\t[%d] %s \t [%d] %s'%(i+1,arr[i],i+2,arr[i+1])
			i += 2
		else:
			print '\t[%d] %s'%(i+1,arr[i])
			i += 1
	print '\n0) Back'
	try:
		choice = (raw_input('> '))
		if 'info' in choice:
			Error('Module \'info\' not implemented yet.')
			#stream.view_info(choice.split(' ')[1])	
			choice = -1
		elif 'quit' in choice:
			# hard quit
			os._exit(1)
		else:
			choice = int(choice)
	except Exception:
		os.system('clear')
		choice = -1
	return choice
