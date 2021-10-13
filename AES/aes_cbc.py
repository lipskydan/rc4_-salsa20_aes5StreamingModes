import pyaes
import os

from tools.time_execution import time_exec

def random(size=16):
    rand = os.urandom(size)
    return rand


class AES_CBC:
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, key, iv):
        assert len(key) in AES_CBC.rounds_by_key_size
        self.iv = [iv[i] for i in range(len(iv))]
        self.aes = pyaes.AES(key)

    def strxor_bytes(self, a, b):
        if len(a) > len(b):
            return [(x ^ y) for (x, y) in zip(a[:len(b)], b)]
        else:
            return [(x ^ y) for (x, y) in zip(a, b[:len(a)])]

    def PKCS_pad(self, text):
        padding_len = 16 - (len(text) % 16)
        for i in range(padding_len):
            text += chr(padding_len)
        return text

    def PKCS_unpad(self, text):
        padding_len = ord(text[-1])
        assert padding_len > 0
        message, padding = text[:-padding_len], text[-padding_len:]
        assert all(ord(p) == padding_len for p in padding)
        return message

    def split_16bytes(self, message):
        assert len(message) % 16 == 0
        message_16bytes = [message[i:i + 16] for i in range(0, len(message), 16)]
        return message_16bytes

    def encrypt_cbc(self, text):
        iv = self.iv
        text = self.PKCS_pad(text)

        blocks = []
        previous = iv.copy()

        for text_block in self.split_16bytes(text):
            text_block_bytes = [ord(c) for c in text_block]
            block = self.aes.encrypt(self.strxor_bytes(text_block_bytes, previous))
            blocks.extend(block)
            previous = block

        return "".join([chr(blocks[i]) for i in range(len(blocks))])

    def decrypt_cbc(self, cipher):
        iv = self.iv

        blocks = []
        previous = iv.copy()

        for cipher_block in self.split_16bytes(cipher):
            cipher_block_bytes = [ord(c) for c in cipher_block]
            block = self.strxor_bytes(previous, self.aes.decrypt(cipher_block_bytes))
            blocks.extend(block)
            previous = cipher_block_bytes

        return self.PKCS_unpad("".join([chr(blocks[i]) for i in range(len(blocks))]))


@time_exec
def aes_cbc(plaintext, key, show=False):
    iv = b'initializationVe'

    aes = AES_CBC(key, iv)

    ciphertext = aes.encrypt_cbc(plaintext)
    if show:
        print("-----------------------------")
        print('ciphertext AES_CBC:', ciphertext)

    decrypted = aes.decrypt_cbc(ciphertext)
    if show:
        print('decrypted by AES_CBC:', decrypted)
        print("-----------------------------\n")