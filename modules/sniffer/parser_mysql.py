import util

class ResponseStruct:
	""" Response structure """
	def __init__(self):
		self.pkt_length	= 0
		self.num 		= 0
		self.catalog	= None
		self.database	= None
		self.table		= None
		self.orig_table	= None
		self.name		= None
		self.orig_name	= None
		self.char_num	= 0
		self.length		= 0
		self.type		= 0
		self.flags		= 0
		self.decimals	= 0

def endian_int(arr):
	"""Parse string array bytes into an int"""
	arr.reverse()
	return int(''.join(arr), 16)

def num_fields(pkt):
	"""Return the number of fields in a query response"""
	return int(pkt[4], 16)

def parse_layer(layer):
	"""Returns a ResponseStruct of the request layer.
	"""
	struct = ResponseStruct()
	# packet length
	struct.pkt_length = endian_int(layer[0:3])
	layer = layer[3:]
	# packet number
	struct.num = int(layer[0], 16)
	layer = layer[1:]
	# catalog
	ltmp = int(layer[0], 16)
	struct.catalog = ''.join(layer[1:ltmp+1]).decode('hex')
	layer = layer[ltmp+1:]
	# database
	ltmp = int(layer[0], 16)
	if ltmp > 0:
		struct.database = ''.join(layer[1:ltmp+1]).decode('hex')
		layer = layer[ltmp+1:]
	else:
		layer = layer[1:]
	# table
	ltmp = int(layer[0], 16)
	if ltmp > 0:
		struct.table = ''.join(layer[1:ltmp+1]).decode('hex')
		layer = layer[ltmp+1:]
	else:
		layer = layer[1:]
	# original table
	ltmp = int(layer[0], 16)
	if ltmp > 0:
		struct.orig_table = ''.join(layer[1:ltmp+1]).decode('hex')
		layer = layer[ltmp+1:]
	else:
		layer = layer[1:]
	# name
	ltmp = int(layer[0], 16)
	if ltmp > 0:
		struct.name = ''.join(layer[1:ltmp+1]).decode('hex')
		layer = layer[ltmp+1:]
	else:
		layer = layer[1:]
	# original name
	ltmp = int(layer[0], 16)
	if ltmp > 0:
		struct.orig_name = ''.join(layer[1:ltmp+1]).decode('hex')
		layer = layer[ltmp+1:]
	else:
		layer = layer[1:]
	# charset number
	struct.char_num = endian_int(layer[1:3])
	layer = layer[3:]
	# length
	struct.length = endian_int(layer[0:4])
	layer = layer[4:]
	# type
	struct.type = int(layer[0], 16)
	layer = layer[1:]
	# flags
	struct.flags = layer[0:2]
	layer = layer[2:]
	# decimals	
	struct.decimals = int(layer[0],16)
	return struct

def verify_header(pkt):
	"""Not all packets have a MySQL header, so verify
	   if it's there.
	"""
	if endian_int(pkt[0:3]) is 1:
		if int(pkt[3],16) is 1:
			return True
	return False

def is_error(pkt):
	"""Check if the query response is an error"""
	code = endian_int(pkt[5:7])
	if code == 1064:
		# error in SQL query
		return True
	elif code == 1096:
		# no tables used
		return True
	return False

def is_okay(pkt):
	"""Check if the packet is an ACK"""
	if int(pkt[0],16) == 7:
		if set(pkt) == set(['07','00','00','01',
						    '00','00','00','02',
							'00','00','00']):
			return True
	return False

def parse_response_data(layer, fields):
	"""Parse the data from a response"""
	length = endian_int(layer[0:3])
	layer = layer[4:]

	response = []
	for i in xrange(fields):
		ltxt = int(layer[0],16)
		text = ''.join(layer[1:ltxt+1]).decode('hex')
		response.append(text)
		layer = layer[ltxt+1:]
	return response 

def is_eof_layer(layer):
	"""Check if layer is an EOF layer"""
	if int(layer[4],16) is 254:
		return True
	return False

def get_layer(num, pkt):
	"""Returns a specific entry in the MySQL packet.
	   @param num is the layer number in the response packet.
	   @param pkt is the raw packet.
	"""
	for i in range(0, num):
		layer_len = endian_int(pkt[0:3])
		if num > 0:
			layer_len += 4 # account for the first packet's offset
		pkt = pkt[layer_len:]

	if len(pkt) is 0:
		return None

	# knock off the rest
	layer_len = endian_int(pkt[0:3])
	return pkt[0:layer_len+4]

def get_response(pkt):
	"""Parse a Response packet.  Given a raw query response
	   packet, this will parse out the columns and text.
	   Returned is a tuple of (columns, data)
	"""
	header = True
	num = num_fields(pkt)

	# not all mysql responses have headers...
	if verify_header(pkt):
		pkt = pkt[5:]
	else:
		header = False

	columns = []
	response = []

	# check if packet is an error packet
	if is_error(pkt):
		return (None,None)
	
	# parse columns
	tmp = 0
	while True:
		try:
			column = get_layer(tmp, pkt)
			if column is None or is_eof_layer(column):
				break
			struct = parse_layer(column)
			columns.append(struct)
			tmp += 1
		except:
			return (None,None)

	# parse returned data
	if header and is_eof_layer(get_layer(num, pkt)):
		layers = 1
		while True:
			try:
				layer = get_layer(num+layers, pkt)
				if is_eof_layer(layer):
					break
				response.append(parse_response_data(layer,num))
				layers += 1
			except:
				break
	return (columns, response)
