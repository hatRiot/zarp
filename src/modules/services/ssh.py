import util
import os
import socket
import paramiko
from threading import Thread
from service import Service
from time import sleep
from stubssh import SSHStub, SSHHandler
from zoption import Zoption


class ssh(Service):
    def __init__(self):
        super(ssh, self).__init__('SSH Server')
        self.config.update({"priv_key":Zoption(type = "str",
                                        value = None,
                                        required = False,
                                    display = "Private key (None to generate)")
                           })
        self.info = """
                    Emulate a basic SSH service; stores usernames/passwords
                    but rejects requests.
                    """

    def cleanup(self):
        """ If we weren't given a private key, remove the temp we generated
        """
        if self.config['priv_key'].value == './privkey.key':
            os.system('rm -f privkey.key')

    def initialize_bg(self):
        if self.config['priv_key'].value is not None:
            paramiko.RSAKey.from_private_key_file( \
                                    self.config['priv_key'].value)
        util.Msg('Initializing SSH server...')
        thread = Thread(target=self.initialize)
        thread.start()

        sleep(1)
        if self.running:
            return True
        else:
            return False

    def initialize(self):
        priv_key = self.config['priv_key'].value
        try:
            # try importing here so we can catch it right away
            import paramiko
        except ImportError:
            util.Error('Paramiko libraries required for this module.')
            return

        level = getattr(paramiko.common, 'CRITICAL')
        paramiko.common.logging.basicConfig(level=level)
        # if the user did not specify a key, generate one
        if priv_key is None:
            if not util.check_program('openssl'):
                util.Error('OpenSSL required to generate cert/key files.')
                return
            if not util.does_file_exist('./privkey.key'):
                util.debug('Generating RSA private key...')
                util.init_app('openssl genrsa -out privkey.key 2048')
                util.debug('privkey.key was generated.')
            priv_key = self.config['priv_key'].value = './privkey.key'

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            server_socket.settimeout(3)
            server_socket.bind(('0.0.0.0', 22))
            server_socket.listen(1)
            self.running = True

            while self.running:
                try:
                    con, addr = server_socket.accept()
                except KeyboardInterrupt:
                    return
                except:
                    # timeout
                    continue

                pkey = paramiko.RSAKey.from_private_key_file(priv_key)
                transport = paramiko.Transport(con)
                transport.add_server_key(pkey)
                transport.set_subsystem_handler('handler', paramiko.SFTPServer, SSHHandler)

                context = {'dump': self.dump, 'log_data': self.log_data,
                            'log_file': self.log_file}
                server = SSHStub(context)
                try:
                    transport.start_server(server=server)
                    transport.accept()
                    while transport.is_active():
                        sleep(1)
                except socket.error as j:
                    if j.errno == 104:
                        # just means we've got a broken pipe, or
                        # the peer dropped unexpectedly
                        continue
                    else:
                        raise Exception()
                except IOError:
                    util.Error('There was an error reading the keyfile.')
                    return False
                except EOFError:
                    # thrown when we dont get the key correctly, or
                    # remote host gets mad because the key changed
                    continue
                except:
                    raise Exception()
        except KeyboardInterrupt:
            pass
        except Exception as j:
            util.Error('Error with server: %s' % j)
        finally:
            self.running = False
            self.cleanup()

    def cli(self, parser):
        """ initialize CLI options
        """
        parser.add_argument('--ssh', help='SSH Server', action='store_true',
                                default=False, dest=self.which)
