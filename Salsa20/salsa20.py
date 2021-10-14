import os
from tools.time_execution import time_exec


def rot_left(x, y): return ((x << y) % (2 ** 32 - 1))


def quarterround(y):
    assert len(y) == 4
    z = [0] * 4
    z[1] = y[1] ^ rot_left(((y[0] + y[3]) % 2 ** 32), 7)
    z[2] = y[2] ^ rot_left(((z[1] + y[0]) % 2 ** 32), 9)
    z[3] = y[3] ^ rot_left(((z[2] + z[1]) % 2 ** 32), 13)
    z[0] = y[0] ^ rot_left(((z[3] + z[2]) % 2 ** 32), 18)
    return z


def rowround(y):
    assert len(y) == 16
    z = [0] * 16
    z[0], z[1], z[2], z[3] = quarterround([y[0], y[1], y[2], y[3]])
    z[5], z[6], z[7], z[4] = quarterround([y[5], y[6], y[7], y[4]])
    z[10], z[11], z[8], z[9] = quarterround([y[10], y[11], y[8], y[9]])
    z[15], z[12], z[13], z[14] = quarterround([y[15], y[12], y[13], y[14]])
    return z


def columnround(x):
    assert len(x) == 16
    y = [0] * 16
    y[0], y[4], y[8], y[12] = quarterround([x[0], x[4], x[8], x[12]])
    y[5], y[9], y[13], y[1] = quarterround([x[5], x[9], x[13], x[1]])
    y[10], y[14], y[2], y[6] = quarterround([x[10], x[14], x[2], x[6]])
    y[15], y[3], y[7], y[11] = quarterround([x[15], x[3], x[7], x[11]])
    return y


def doubleround(x):
    return rowround(columnround(x))


def littleendian(b):
    assert len(b) == 4
    return b[0] ^ (b[1] << 8) ^ (b[2] << 16) ^ (b[3] << 24)


def littleendian_invert(w):
    return [w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >> 24) & 0xff]


# assert littleendian_invert(0x091e4b56) == [86, 75, 30, 9]
# assert littleendian_invert(0xfaffffff) == [255, 255, 255, 250]


def salsa_20_hash(x):
    _x = [0] * 16
    i = 0
    k = 0
    while i < 16:
        _x[i] = littleendian([x[k], x[k + 1], x[k + 2], x[k + 3]])
        k += 4
        i += 1

    z = _x
    for j in range(10):
        z = doubleround(z)

    y = []
    for i in range(16):
        w = z[i] + _x[i]
        y.append(w & 0xff)
        y.append((w >> 8) & 0xff)
        y.append((w >> 16) & 0xff)
        y.append((w >> 24) & 0xff)

    return y


def salsa_20_hash_invert(x):
    _x = [0] * 16
    i = 0
    k = 0
    while i < 16:
        _x[i] = littleendian([x[k], x[k + 1], x[k + 2], x[k + 3]])
        k += 4
        i += 1

    z = _x
    for j in range(10):
        z = doubleround(z)

    y = []
    for i in range(16):
        w = z[i] + _x[i]
        y.append(w & 0xff)
        y.append((w >> 8) & 0xff)
        y.append((w >> 16) & 0xff)
        y.append((w >> 24) & 0xff)

    return y


sig_0 = [101, 120, 112, 97]
sig_1 = [110, 100, 32, 51]
sig_2 = [50, 45, 98, 121]
sig_3 = [116, 101, 32, 107]


def encrypt(plaintext, nonce, key):
    assert len(nonce) == 8
    assert len(key) == 32
    _nonce = list(nonce)
    _key = list(key)
    block_counter = [0] * 8
    k0 = _key[:16]
    k1 = _key[16:]
    enc_list = [a ^ b for a, b in
                zip(salsa_20_hash(sig_0 + k0 + sig_1 + _nonce + block_counter + sig_2 + k1 + sig_3), list(plaintext))]
    return bytearray(enc_list)


def decrypt(ciphertext, nonce, key):
    assert len(nonce) == 8
    assert len(key) == 32
    _nonce = list(nonce)
    _key = list(key)
    block_counter = [0] * 8
    k0 = _key[:16]
    k1 = _key[16:]
    enc_list = [a ^ b for a, b in
                zip(salsa_20_hash(sig_0 + k0 + sig_1 + _nonce + block_counter + sig_2 + k1 + sig_3), list(ciphertext))]
    return bytearray(enc_list)


@time_exec
def salsa20(plaintext, key='', show=False):
    key = bytearray(range(1, 33))
    nonce = bytearray([3, 1, 4, 1, 5, 9, 2, 6])
    ciphertext = encrypt(plaintext=plaintext.encode('UTF-8'), nonce=nonce, key=key)

    if show:
        print("-----------------------------")
        print('ciphertext Salsa20:', ciphertext)
        print("-----------------------------\n")

    decrypted = decrypt(ciphertext=ciphertext, nonce=nonce, key=key).decode("utf-8")

    if show:
        print('decrypted by Salsa20:', decrypted)
        print("-----------------------------\n")
