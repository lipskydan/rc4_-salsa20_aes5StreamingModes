import rc4, salsa20
import time


def main():
    plaintext = 'Good work! Your implementation is correct'
    print('plaintext:', plaintext)

    rc4.run(plaintext=plaintext, show=True)
    salsa20.run(plaintext=plaintext, show=True)

    start = time.time()
    for i in range(1000): rc4.run(plaintext=plaintext)
    end = time.time()

    print(f'RC4 1000 times works {end - start} s')

    start = time.time()
    for i in range(1000): salsa20.run(plaintext=plaintext)
    end = time.time()

    print(f'Salsa20 1000 times works {end - start} s')


if __name__ == '__main__':
    main()
