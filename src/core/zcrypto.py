from base64 import b64encode, b64decode
from hashlib import sha256
from random import SystemRandom, getrandbits

""" zarp crypto module for implementing various cryptographic algorithms
    that I might need standard implementations of.
"""


class DH:
    """Diffie hellman for generating shared key. Thanks to the following for
       implementation tips:
       http://blog.markloiseau.com/2013/01/diffie-hellman-tutorial-in-python/
    """
    # 6144-bit MODP prime from RFC 3526
    prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF

    def __init__(self):
        self.shared_secret = None
        self.shared_key = None
        self.generator = 2
        self.private = self.gen_private()
        self.public = self.gen_public()

    def gen_private(self):
        """Return a private key"""
        try:
            return SystemRandom().getrandbits(576)
        except:
            # if OS doesnt provide a urand pool, use mersenne
            return getrandbits(576)

    def gen_public(self):
        """Return a public key with g**x%p"""
        return pow(self.generator, self.private, self.prime)

    def check_pubkey(self, key):
        """Check if the given key is valid"""
        if key > 2 and key < self.prime - 1:
            if pow(key, (self.prime - 1) / 2, self.prime) == 1:
                return True
        return False

    def generate_secret(self, private_key, key):
        """Check if key is valid, then generate a shared
           secret with it
        """
        if self.check_pubkey(key):
            # valid pubkey
            secret = pow(key, private_key, self.prime)
            return secret

    def generate_key(self, key):
        """Generate the shared key"""
        self.shared_secret = self.generate_secret(self.private, key)
        hsh = sha256()
        hsh.update(str(self.shared_secret))
        self.shared_key = hsh.digest()


class RC4:
    """RC4.  Encrypted data is b64'd, and the decryption
       routine expects b64'd data as well.
    """

    def __init__(self):
        self.key = None

    def crypt(self, data):
        """Apply the [en|de]cryption routine
           to the data.
        """
        x = 0
        box = range(256)
        for i in range(256):
            x = (x + box[i] + ord(self.key[i % len(self.key)])) & 0xff
            box[i], box[x] = box[x], box[i]
        x = y = 0
        out = []
        for char in data:
            x = (x + 1) & 0xff
            y = (y + box[x]) & 0xff
            box[x], box[y] = box[y], box[x]
            out.append(chr(ord(char) ^ box[(box[x] + box[y]) & 0xff]))
        return ''.join(out)

    def encrypt(self, data):
        """Encrypt the data and b64 encode"""
        if self.key is None:
            return None
        return b64encode(self.crypt(data))

    def decrypt(self, data):
        """Decode the b64 data and perform the RC4 alg"""
        if self.key is None:
            return None
        return self.crypt(b64decode(data))