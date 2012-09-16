#
# Class houses utility functions
#

# zarp version
def version():
	return 0.02

# zarp header
def header():
	print "\t        [\033[31mZARP\033[0m]\t\t" #red
	print "\t    [\033[33mVersion %s\033[0m]\t\t\t"%(version()) #yellow
