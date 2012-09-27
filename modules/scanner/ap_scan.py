from scapy.all import *
from threading import Thread
from commands import getoutput
import sys, os

#
# scan for wireless APs.  useful when searching for WEP or unprotected APs.
#
unique = []
scanning = False

def initialize():
	global scanning
	conf.verbose = 0
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
	hop_thread = Thread(target=hops, args=[adapt])		
	hop_thread.start()
	time.sleep(1)	# let channel hopping set up
	try:
		print '[!] Scanning for access points...'
		print '{0:25} {1:30} {2:35}'.format('SSID','MAC','PRIVACY')
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
			tmp = pkt.sprintf("\t[%Dot11Elt.info%|%Dot11Beacon.cap%]")
			print '[+] {0:20} {1:30} {2:35}'.format(pkt[Dot11Elt].info, pkt.addr2,'Encrypted' if ('privacy' 
									in tmp)	else 'Unencrypted')
			unique.append(pkt.addr2)

#
# Hop channels to find different APs
#
def hops(adapter):
	global scanning
	# not all cards support this
	tmp = getoutput('iwconfig %s channel %d'%(adapter, 2))
	if 'SET failed on device' in tmp:
		print '[-] \'%s\' does not support channel hopping.  Disabling...'%adapter
		return False
	print '[dbg] starting channel hopper with device [%s]'%adapter
	while scanning:
		try:
			channel = random.randrange(1,15)
			os.system("iwconfig %s channel %d"%(adapter, channel))
			time.sleep(2)
		except Exception,e:
			print '[ERR] ', e
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
