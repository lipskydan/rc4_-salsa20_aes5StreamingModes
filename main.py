import rc4, salsa20, aes
import time


def main():
    TIMES = 1000

    plaintext = 'Good work! Your implementation is correct'
    print('plaintext:', plaintext)

    rc4.run(plaintext=plaintext, show=True)
    salsa20.run(plaintext=plaintext, show=True)
    aes.run(plaintext=plaintext, show=True)

    start = time.time()
    for i in range(TIMES): rc4.run(plaintext=plaintext)
    end = time.time()

    print(f'RC4 {TIMES} times works {end - start}s')

    start = time.time()
    for i in range(TIMES): salsa20.run(plaintext=plaintext)
    end = time.time()

    print(f'Salsa20 {TIMES} times works {end - start}s')

    start = time.time()
    for i in range(TIMES): aes.run(plaintext=plaintext)
    end = time.time()

    print(f'AES {TIMES} times works {end - start}s')


if __name__ == '__main__':
    main()
