#
# Class houses utility functions
#

# zarp version
def version():
	return 0.02

# zarp header
def header():
	print "\t        [\033[31mZARP\033[0m]\t\t" #red
	print "\t    [\033[33mVersion %s\033[0m]\t\t\t"%(version()) #yellow

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
