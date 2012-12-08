import paramiko
import util

#
# Handler for credentials
#
class SSHStub(paramiko.ServerInterface):
	def __init__(self, context, *args):
		self.context = context
		paramiko.ServerInterface.__init__(self, *args)

	# handle credentials and always reject 
	def check_auth_password(self, username, password):
		if self.context['dump']:
			util.Msg('Received login attempt: %s:%s'%(username, password))
		if self.context['log_data']:
			self.context['log_file'].write('Received login: %s:%s\n'%(username, password))
		return paramiko.AUTH_FAILED

	def check_channel_request(self, kind, chanid):
		return paramiko.OPEN_SUCCEEDED

class SSHHandler(paramiko.SFTPServerInterface):
	pass
