import sys, os
sys.path.insert(0, os.getcwd() + '/modules/parameter/routers/')
import dlink, util

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
			pass
		elif choice == 3:
			pass
		elif choice == 4:
			pass
		else:
			break
			
