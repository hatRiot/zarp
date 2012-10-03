import util

def vulnerabilities():
	return [ 'Remote Execution' ]

def run ( run ):
	if run == 1:
		tmp = vulnerabilities()[run-1]
		print '[dbg] running ',tmp
		return
