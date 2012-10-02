#!/bin/bash

#
# Setup script for Zarp.
#

# retrieve and install Scapy
function install(){
	echo '[+] Fetching latest Scapy...'
	wget scapy.net 
	mv ./index.html ./scapy.zip
	unzip scapy.zip
	cd scapy-*
	sudo python setup.py install
	echo '[!] Cleaning up...'
	cd ../
	rm -fr ./scapy*
}

# patch scapy with modified classes
function patch(){
	echo '[+] Patching scapy...'
    if [ -d '/usr/local/lib/python2.7/site-packages/scapy/' ]; then
      # patch sendrecv.py
      SCAPY_INSTALL='/usr/local/lib/python2.7/site-packages/scapy'
      mv $SCAPY_INSTALL/sendrecv.py $SCAPY_INSTALL/sendrecv_backup.py 2>/dev/null
      cp ./install/sendrecv.py $SCAPY_INSTALL/sendrecv.py
	elif [ -d '/usr/local/lib/python2.6/dist-packages/scapy/' ]; then
	  # patch sendrecv.py
	  SCAPY_INSTALL='/usr/local/lib/python2.6/dist-packages/scapy'
	  mv $SCAPY_INSTALL/sendrecv.py $SCAPY_INSTALL/sendrecv_backup.py 2>/dev/null
	  cp ./install/sendrecv.py $SCAPY_INSTALL/sendrecv.py 
    else
	  # TODO: find and replace automatically
	  echo -n '[!] Enter scapy install directory: '
	  read SCAPY_INSTALL
	  if [ -d $SCAPY_INSTALL ]; then
	    mv $SCAPY_INSTALL/sendrecv.py $SCAPY_INSTALL/sendrecv_backup.py 2>/dev/null
		cp ./install/sendrecv.py $SCAPY_INSTALL/sendrecv.py
	  else
	    echo '[-] $SCAPY_INSTALL does not exist or is incorrect.  Exiting...'
		exit 1
	  fi
	fi
	# remove the byte-compiled version
	rm -f $SCAPY_INSTALL/sendrecv.pyc
}

# we need privs to move stuff around
if [ "$(id -u)" != '0' ]; then 
  echo '[-] Script needs to be run as root.'
  exit 1
fi

# check for python
PYTHON=`which python`
if [ ! -f $PYTHON ]; then
  echo '[-] Python not found!'
  exit 1
fi

# check version
PY_VER=`$PYTHON -c 'import sys 
print (sys.version_info >= (2,6) and "1" or "0")'`
if [ "$PY_VER" = '0' ]; then
  echo '[-] Zarp requires Python 2.6 or later.'
  exit 1
fi

# test if Scapy is correctly installed
echo '[!] Checking for Scapy...'
SCAPY_EXISTS=`$PYTHON -c 'try:
	import logging
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	from scapy.all import *
except ImportError:
	print 0
else:
	print 1'`

if [ "SCAPY_EXISTS" = '0' ]; then
  echo '[-] Scapy must first be installed.'
  exit 1
fi

# copy the patched sendrecv.py file
echo '[!] Patching Scapy...'
if [ -d '/usr/local/lib/python2.7/site-packages/scapy/' ]; then
  # patch sendrecv.py
  SCAPY_INSTALL='/usr/local/lib/python2.7/site-packages/scapy'
  mv $SCAPY_INSTALL/sendrecv.py $SCAPY_INSTALL/sendrecv_backup.py 2>/dev/null
  cp ./install/sendrecv.py $SCAPY_INSTALL/sendrecv.py
  rm -f $SCAPY_INSTALL/sendrecv.pyc
elif [ -d '/usr/local/lib/python2.6/dist-packages/scapy' ]; then
  # patch sendrecv.py
  SCAPY_INSTALL='/usr/local/lib/python2.6/dist-packages/scapy'
  mv $SCAPY_INSTALL/sendrecv.py $SCAPY_INSTALL/sendrecv_backup.py 2>/dev/null
  cp ./install/sendrecv.py $SCAPY_INSTALL/sendrecv.py
  rm -f $SCAPY_INSTALL/sendrecv.pyc
else
  echo '[-] Default scapy path not found.  Should be around /usr/local/lib/python2.[6|7]/site-packages/scapy'
  echo -n '[-] Specify scapy install location: '
  read SCAPY_INSTALL
  if [ -d "$SCAPY_INSTALL" ]; then
    mv $SCAPY_INSTALL/sendrecv.py $SCAPY_INSTALL/sendrecv_backup.py 2>/dev/null
	cp ./install/sendrecv.py $SCAPY_INSTALL/sendrecv.py
  rm -f $SCAPY_INSTALL/sendrecv.pyc
  else
    echo -n '[-] Scapy install not found.  Enter "y" to download and install, or "n" to exit: '
	read TMP
	if [ "$TMP" == 'n' ]; then
	  exit 1
	else
	  install
	  patch
	fi
  fi
fi

# check for airodump-ng, but dont install
AD= `which airodump-ng`
if [ $AD == '' ]; then
  echo '[-] Airodump-ng not found.  This is required for any wireless modules.'
fi

# check IP forwarding
FORWARDING=`cat /proc/sys/net/ipv4/ip_forward`
if [ $FORWARDING == '0' ]; then
  echo '[-] IPv4 forwarding is disabled.  Enabling...'
  sudo sh -c 'echo "1" > /proc/sys/net/ipv4/ip_forward'
fi

echo -e "[+] Zarp install complete.  Run with:\n\tsudo python zarp.py"
