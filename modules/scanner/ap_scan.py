from scapy.all import *
from threading import Thread
import sys, os

#
# scan for wireless APs.  useful when searching for WEP or unprotected APs.
#
unique = []
scanning = False

def initialize():
	global scanning
	try:
		iface = raw_input('[!] Enter monitoring wireless interface [%s]: '%conf.iface)
		if len(iface) <= 0:
			iface = conf.iface
		print '[dbg] using interface %s'%iface
		ap_scan(iface)
	except Exception, KeyboardInterrupt:
		return

#
# Sniff on the monitoring adapter and hand off packets
#
def ap_scan(adapt):
	global scanning
	scanning = True
#hop_thread = Thread(target=hops, args=[adapt])		
#	hop_thread.start()
	print '[dbg] is scanning: ', scanning
	try:
		print '[!] Scanning for access points...'
		sniff(iface=adapt, prn=sniffBeacon, stopper=stop_callback, stopperTimeout=3)
	except KeyboardInterrupt:
		scanning = False
		print '[!] Exiting..'

#
# Parse out beacons and dump info
#
def sniffBeacon(pkt):
	if pkt.haslayer(Dot11Beacon):
		if not pkt.addr2 in unique:
			print '[+] Address: ', pkt.addr2
			print pkt.sprintf("\t[%Dot11Elt.info%|%Dot11Beacon.cap%]")
			if pkt[Dot11Elt].ID == 221 and pkt[Dot11Elt].info.startswith("\x00P\xf2\x02"):
				print "[!] WPA Enabled"
			unique.append(pkt.addr2)
	# potential hidden SSID's
	if pkt.haslayer(Dot11ProbeReq) and not pkt.addr1 in unique:
		print '[+] Hidden SSID found: ', pkt.addr1
		print pkt.sprintf("\t[%Dot11Elt.info%|%Dot11Beacon.cap%]")
		print pkt.fields
	if pkt.haslayer(Dot11WEP):
		print struct.unpack("!I", pkt[Dot11WEP].wepdata[-4:])
		print 'wep data: ',pkt[Dot11WEP].wepdata[:-4]
		print '[dbg] key id: ',pkt[Dot11WEP].keyid
		print '[dbg] icv: ',pkt[Dot11WEP].icv
	if pkt.haslayer(PrismHeader):
		print 'channel: ',pkt[PrismHeader].Channel
		print 'Rate: ',pkt[PrismHeader].Rate
	

#
# Hop channels to find different APs
# credit: airoscapy.py @iphelix
#
def hops(adapter):
	global scanning
	print '[dbg] starting channel hopper with device [%s]'%adapter
	while scanning:
		try:
			channel = random.randrange(1,15)
			os.system("iw dev %s set channel %d"%(adapter, channel))
			time.sleep(2)
		except Exception:
			break
	print '[dbg] stopping channel hopper..'

#
# Callback for stopping the sniffer
#
def stop_callback():
	global scanning
	if scanning:
		return False
	print '[-] Shutting down...'
	return True
