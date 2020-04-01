"""
Description: Provide cryptographic functionality for the python tools.
Use: Do not run directly. This module is used by other tools scripts.
"""
import hashlib

class Cipher(object):
    """Object to encrypt or decrypt data"""

    def __init__(self, key):
        """initialize values
        Args:
            key (_): key to encrypt/decrypt data
        """
        self.key = key
        #self.iv = randomness
    
    def encrypt(self, pt):
        """encrypt data
        Args:
            py (bytes): the plaintext message to encrypt
        """
        speck = SpeckCipher(key,256,128,'CBC')
        #finish writing this method

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
