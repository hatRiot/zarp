import util
import struct

def endian_int(pkt):
	"""Return an integer from an array of hex bytes"""
	return int(''.join(pkt),16)

def parse_query(pkt):
	"""Parse and return a query"""
	length = endian_int(pkt[1:5])

	pkt = pkt[5:]
	query = ''
	for i in xrange(length-4):
		query += pkt[i].decode('hex')
	return query

def database_exists(pkt):
	"""Parse the database packet, return if it
	   checks out or not.
	"""
	found = True
	if pkt[9] == '45':
		found = False
	return found
	

def is_ssl(pkt):
	"""Check if the packet is an SSL request"""
	if set(pkt) == set(['00','00','00','08',
					    '04','d2','16','2f']):
		return True
	return False
	
def parse_startup(pkt):
	"""Startup packets contain a set of
	   keys and values. Return an array
	   of key/value/key/value/etc..
	"""
	values = []
	plen = endian_int(pkt[0:4])
	pkt = pkt[8:]

	tmp = ''
	for i in xrange(plen-8):
		tmp += pkt[i].decode('hex')
		if pkt[i] == '00':
			values.append(tmp)
			tmp = ''
	return values

def get_columns(pkt):
	"""Parse columns out of a response packet.
	"""
	columns = []
	num_columns = endian_int(pkt[5:7])

	pkt = pkt[7:]
	ctmp = ''
	for column in xrange(num_columns):
		cnt = 0
		while True:
			tmp = pkt[cnt]
			if tmp == '00':
				columns.append(ctmp)
				ctmp = ''
				pkt = pkt[cnt+19:]
				break
			ctmp += tmp.decode('hex')
			cnt += 1

	return (columns, pkt)

def get_row(pkt):
	"""Return a row of data"""
	row = []
	tmp = ''
	fields = endian_int(pkt[0:2])
	pkt = pkt[2:]
	for field in xrange(fields):
		clen = endian_int(pkt[0:4])
		if clen == 4294967295:
			# indicates an empty column
			row.append('')
			continue

		pkt = pkt[4:]
		for i in xrange(clen):
			tmp += pkt[i].decode('hex')
		row.append(tmp)
		pkt = pkt[clen:]
		tmp = ''

	return row

def is_done(pkt):
	"""Check if packet is a Command Completion
	   packet.
	"""
	if pkt[0] == '43':
		return True
	return False

def parse_response(pkt): 
	"""Parse a query response"""
	data = []

	try:
		(columns, pkt) = get_columns(pkt)	
		while True:
			if is_done(pkt):
				break

			dlen = endian_int(pkt[1:5]) + 1
			row = get_row(pkt[5:dlen])
			data.append(row)
			pkt = pkt[dlen:]
	except Exception, e:
		util.debug('Error parsing postgres: %s'%e)

	return (columns, data)

def parse_error(pkt):
	"""Parse an error message"""
	elen = endian_int(pkt[1:5])

	pkt = pkt[20:]
	error = ''
	for idx in xrange(elen-20):
		tmp = pkt[idx]
		if tmp == '00':
			break
		error += tmp.decode('hex')
	return error
