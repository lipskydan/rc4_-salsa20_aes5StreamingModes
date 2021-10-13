import crypto
import sys

sys.modules['Crypto'] = crypto

from crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

from tools.time_execution import time_exec


class AES_ECB(object):

    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    def encrypt(self, text):
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')

        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            text = text + ('\0' * add).encode('utf-8')
        elif count > length:
            add = (length - (count % length))
            text = text + ('\0' * add).encode('utf-8')
        self.ciphertext = cryptor.encrypt(text)

        return b2a_hex(self.ciphertext)

    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        plain_text = cryptor.decrypt(a2b_hex(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip('\0')


@time_exec
def aes_ecb(plaintext, key, show=False):
    aes = AES_ECB(key)

    ciphertext = aes.encrypt(plaintext)
    if show:
        print("-----------------------------")
        print('ciphertext AES_ECB:', ciphertext)

    decrypted = aes.decrypt(ciphertext)
    if show:
        print('decrypted by AES_ECB:', decrypted)
        print("-----------------------------\n")
