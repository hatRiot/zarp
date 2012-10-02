import util

#
# dlink vulnerabilities
#

#
# run the specified vuln
#
def run ( run ):
	if run == 1:
		tmp = vulnerabilities()[run-1]
		print '[dbg] running',tmp
		return

#
# router:vuln
#
def vulnerabilities():
	return [ 'Remote Execution' ]
