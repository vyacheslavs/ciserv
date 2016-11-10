import os

from Crypto import Cipher
from Crypto import Random
import base64

class Nonce:

    bytes = None

    def __init__(self, nfrom = None):

        if nfrom == None:
            self.bytes = Random.new().read(Cipher.AES.block_size)
        else:
            self.bytes = base64.b64decode(nfrom)

    def b64(self):
        return base64.b64encode(self.bytes)

class Verifier:
    bytes = None

    def __init__(self, vfrom):
        self.bytes=base64.b64decode(vfrom)

    def b64(self):
        return base64.b64encode(self.bytes)

class Key:
    bytes = None

    def __init__(self, vfrom):
        self.bytes=base64.b64decode(vfrom)

    def b64(self):
        return base64.b64encode(self.bytes)

def aes_unpad(data):
    pad_len = ord(data[-1])
    if pad_len <= 16:
        return data[:-pad_len]
    else:
        return data

def verify(_nonce, _verifier, _key):
    aes = Cipher.AES.new(_key.bytes, Cipher.AES.MODE_CBC, _nonce.bytes)
    cleartext = aes_unpad(aes.decrypt(_verifier.bytes))
    return _nonce.b64() == cleartext

def aes_pad(data):
    pad_len = 16 - len(data) % 16
    pad_chr = chr(pad_len)
    return data + (pad_chr * pad_len)

def sign(_nonce, _key):
    aes = Cipher.AES.new(_key.bytes, Cipher.AES.MODE_CBC, _nonce.bytes)
    verifier = Verifier(base64.b64encode(aes.encrypt(aes_pad(_nonce.b64()))))

    return verifier

def decrypt(_nonce, _key, data):
    d = base64.b64decode(data)
    aes = Cipher.AES.new(_key.bytes, Cipher.AES.MODE_CBC, _nonce.bytes)
    return aes_unpad(aes.decrypt(d))

def encrypt(_nonce, _key, data):
    aes = Cipher.AES.new(_key.bytes, Cipher.AES.MODE_CBC, _nonce.bytes)
    return base64.b64encode(aes.encrypt(aes_pad(data)))
