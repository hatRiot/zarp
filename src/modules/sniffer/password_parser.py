import util
from re import findall, search
from base64 import b64decode
from scapy.all import *

""" Class houses all of the protocol parsing functions.
	Each parsing routine should return a tuple of the form: (username, password)
"""

def parse_ldap(pkt):
	""" Parse LDAP credentials; only supports simple (0) 
		authentication right now.  Scapy doesn't currently
		support LDAP packets, so we'll do this by hand.
	"""
	payload = pkt[TCP].payload	
	pkt_layer = util.get_layer_bytes(str(payload))
	
	usr, pswd = None, None
	if len(pkt_layer) > 0:
		if pkt_layer[4] == '01':
			# bind request
			usr, pswd = '', ''
			usr_len = int(pkt_layer[11])
			for idx in xrange(usr_len):
				usr += pkt_layer[12+idx].decode('hex')

			pw_len = int(pkt_layer[13+usr_len])
			for idx in xrange(pw_len):
				pswd += pkt_layer[14+usr_len+idx].decode('hex')
	return (usr, pswd)

def parse_http(pkt):
	""" Parse out the username/password from an HTTP request.
		This will also parse out any basic authorization requests.	
	"""
	payload = pkt.getlayer(Raw).load
	usr, pswd = None, None
	if 'username' in payload or 'password' in payload:
		usr = re.search('username=(.*?)(&|$| )',payload)
		pswd = re.search('password=(.*?)(&|$| )',payload)
		if usr is not None:  usr = usr.groups(0)[0]
		if pswd is not None: pswd = pswd.groups(0)[0]
	elif 'Authorization:' in payload:
		pw = re.search('Authorization: Basic (.*)',payload)
		if pw.groups(0) is not None:
			usr = b64decode(pw.groups(0)[0])

	return (usr, pswd)

def parse_ftp(pkt):
	""" Parse out the username or password from FTP
	"""
	payload = str(pkt.sprintf("%Raw.load%"))
	# strip control characters
	payload = payload[:-5]
	usr, pswd = None, None

	if 'USER' in payload:   usr = findall("(?i)USER (.*)", payload)[0]
	elif 'PASS' in payload: pswd = findall("(?i)PASS (.*)", payload)[0]

	return (usr, pswd)

def parse_pkt(pkt):
	""" Initialize parsing of the packet
	"""
	if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.haslayer(Raw):
		return parse_http(pkt)
	elif pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 21:
		return parse_ftp(pkt)
	elif pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 389:
		return parse_ldap(pkt)
	return (None, None)
