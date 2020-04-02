"""
Description: Provide cryptographic functionality for the python tools.
Use: Do not run directly. This module is used by other tools scripts.
"""
import hashlib
import secrets
from speck import SpeckCipher

class Cipher(object):
    """Object to encrypt or decrypt data"""

    def __init__(self, key, iv=secrets.randbits(128)):
        """initialize values
        Args:
            key (int): key to encrypt/decrypt data
        """
        self.key = key
        self.iv = iv
    
    def encrypt(self, pt):
        """encrypt data
        Args:
            pt (bytes): the plaintext message to encrypt
        """
        speck = SpeckCipher(self.key,256,128,'CTR',self.iv)
        extra = len(pt)%16
        return b''.join(speck.encrypt(int.from_bytes(pt[i:i+16],'big')).to_bytes(16,'big')for i in range(0,len(pt)-extra,16)) + speck.encrypt(int.from_bytes(pt[len(pt)-extra:],'big')).to_bytes(16,'big')[16-extra:]

    def decrypt(self, c, extra=0):
        """decrypt data
        Args:
            c (bytes): the ciphertest to decrypt
            extra (int): the length (in bytes) of the final block of plaintext
                            alternatively, the length of the plaintext in bytes (mod 16)
        """
        speck = SpeckCipher(self.key,256,128,'CTR',self.iv)
        return b''.join(speck.decrypt(int.from_bytes(c[i:i+16],'big')).to_bytes(16,'big') for i in range(0,len(c)-extra,16)) + speck.decrypt(int.from_bytes(c[len(c)-extra:],'big')).to_bytes(16,'big')[16-extra:]

def sha(): #currently just an example
    out = []
    sha2 = hashlib.sha256()
    sha2.update(b"Hello")
    out.append(sha2.hexdigest())
    sha2.update(b", world!")
    out.append(sha2.hexdigest())
    sha2_2 = hashlib.sha256()
    sha2_2.update(b'abc')
    out.append(sha2_2.hexdigest())
    return out
