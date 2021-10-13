from Salsa20 import salsa20
from RC4 import rc4
from AES import aes_ctr, aes_ecb, aes_cbc, aes_cfb, aes_ofb


def main():
    plaintext = 'Good work! Your implementation is correct'
    key = b'This_key_for_dem'

    print('plaintext:', plaintext, "\n")

    rc4.rc4(plaintext=plaintext, key='', show=True)
    salsa20.salsa20(plaintext=plaintext, key='', show=True)
    aes_ctr.aes_ctr(plaintext=plaintext, key=key, show=True)
    aes_ecb.aes_ecb(plaintext=plaintext, key=key, show=True)
    aes_cbc.aes_cbc(plaintext=plaintext, key=key, show=True)
    aes_cfb.aes_cfb(plaintext=plaintext, key=key, show=True)
    aes_ofb.aes_ofb(plaintext=plaintext, key='', show=True)

    rc4.rc4(plaintext=plaintext, key='', show=False)
    salsa20.salsa20(plaintext=plaintext, key='', show=False)
    aes_ctr.aes_ctr(plaintext=plaintext, key=key, show=False)
    aes_ecb.aes_ecb(plaintext=plaintext, key=key, show=False)
    aes_cbc.aes_cbc(plaintext=plaintext, key=key, show=False)
    aes_cfb.aes_cfb(plaintext=plaintext, key=key, show=False)
    aes_ofb.aes_ofb(plaintext=plaintext, key='', show=False)


if __name__ == '__main__':
    main()
