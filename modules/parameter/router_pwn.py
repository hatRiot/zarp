import sys, os
sys.path.insert(0, os.getcwd() + '/modules/parameter/routers/')
import dlink, cisco, linksys, netgear, util

#
# Router exploits and vulnerabilities.
#

def initialize():
	menu = [ 'dlink', 'netgear',
			 'linksys', 'cisco' ]
	while True:
		choice = util.print_menu(menu)
		if choice == 1:
			choice = util.print_menu(dlink.vulnerabilities())
			if choice == 0:
				continue
			dlink.run(choice)
		elif choice == 2:
			choice = util.print_menu(netgear.vulnerabilities())
			if choice == 0:
				continue
			netgear.run(choice)
		elif choice == 3:
			choice = util.print_menu(linksys.vulnerabilities())
			if choice == 0:
				continue
			linksys.run(choice)
		elif choice == 4:
			choice = util.print_menu(cisco.vulnerabilities())
			if choice == 0:
				continue
			cisco.run(choice)
		elif choice == 0:
			break
		else:
			os.system('clear')
			
