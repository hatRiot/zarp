import util, os

#
# Interfaces with Wifite to crack APs
#
def initialize(crack):
	util.Msg('Initializing Wifite...')
	cmd = []
	if crack is 'wep':
		cmd = [ 'python', 
				'modules/parameter/wifite.py',
		        '--wep', 
				'--wept', '300',
				'--nofakeauth' ]
	elif crack is 'wpa':
		cmd = [ 'python',
				'modules/parameter/wifite.py',
				'--wpa',
				'--wpat', '10',
				'--wpadt', '2' ]
	elif crack is 'wps':
		cmd = [ 'python',
				'modules/parameter/wifite.py', 
				'--wps',
				'--wpst', '5',
				'--wpsretry', '8' ]

	if len(cmd) > 1:
		try:
			os.system(' '.join(cmd))
		except KeyboardInterrupt:
			pass
		except Exception, j:
			util.Error('Error initializing Wifite: %s'%j)

