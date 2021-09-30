from Salsa20 import salsa20
from RC4 import rc4
from AES import aes_ctr, aes_ecb, aes_cbc
import time


def main():
    TIMES = 1000

    plaintext = 'Good work! Your implementation is correct'
    print('plaintext:', plaintext, "\n")

    rc4.run(plaintext=plaintext, show=True)
    salsa20.run(plaintext=plaintext, show=True)
    aes_ctr.run(plaintext=plaintext, show=True)
    aes_ecb.run(plaintext=plaintext, show=True)
    aes_cbc.run(plaintext=plaintext, show=True)

    # start = time.time()
    # for i in range(TIMES): rc4.run(plaintext=plaintext)
    # end = time.time()
    #
    # print(f'RC4 {TIMES} times works {end - start}s')
    #
    # start = time.time()
    # for i in range(TIMES): salsa20.run(plaintext=plaintext)
    # end = time.time()
    #
    # print(f'Salsa20 {TIMES} times works {end - start}s')
    #
    # start = time.time()
    # for i in range(TIMES): aes_ctr.run(plaintext=plaintext)
    # end = time.time()
    #
    # print(f'AES_CTR {TIMES} times works {end - start}s')


if __name__ == '__main__':
    main()
