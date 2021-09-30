import crypto
import sys

sys.modules['Crypto'] = crypto

from crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from crypto import Random
import base64


class AES_CFB():
    def __init__(self, key, mode=AES.MODE_CFB):
        self.key = self.check_key(key)
        self.mode = mode
        self.iv = Random.new().read(AES.block_size)

    def check_key(self, key):
        '检测key的长度是否为16,24或者32bytes的长度'
        try:
            if isinstance(key, bytes):
                assert len(key) in [16, 24, 32]
                return key
            elif isinstance(key, str):
                assert len(key.encode()) in [16, 24, 32]
                return key.encode()
            else:
                raise Exception(f'密钥必须为str或bytes,不能为{type(key)}')
        except AssertionError:
            print('输入的长度不正确')

    def check_data(self, data):
        '检测加密的数据类型'
        if isinstance(data, str):
            data = data.encode()
        elif isinstance(data, bytes):
            pass
        else:
            raise Exception(f'加密的数据必须为str或bytes,不能为{type(data)}')
        return data

    def encrypt(self, data):
        ' 加密函数 '
        data = self.check_data(data)
        cryptor = AES.new(self.key, self.mode, self.iv)
        return b2a_hex(cryptor.encrypt(data)).decode()

    def decrypt(self, data):
        ' 解密函数 '
        data = self.check_data(data)
        cryptor = AES.new(self.key, self.mode, self.iv)
        return cryptor.decrypt(a2b_hex(data)).decode()


def run(plaintext, key, show=False):
    aes = AES_CFB(key)

    ciphertext = aes.encrypt(plaintext)

    if show:
        print("-----------------------------")
        print('ciphertext AES_CFB:', ciphertext)

    decrypted = aes.decrypt(ciphertext)
    if show:
        print('decrypted by AES_CFB:', decrypted)
        print("-----------------------------\n")
