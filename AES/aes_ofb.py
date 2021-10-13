import random
from AES import aes

from tools.time_execution import time_exec

def chunks(string, blockSize):
    for i in range(0, len(string), blockSize):
        yield string[i:i + blockSize]

def randomIV(length):
    IV = ""
    for l in range(0, length):
        IV = IV + str(random.randint(0, 1))

    return IV


def dummyIV():
    ivArray = list("01010000")
    for i in range(0, len(ivArray)):
        ivArray[i] = int(ivArray[i])

    return ivArray


def binvalue(val, bitsize):
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise ("binary value larger than the expected size")
    while len(binval) < bitsize:
        binval = "0" + binval
    return binval


def nsplit(s, n):
    return [s[k:k + n] for k in xrange(0, len(s), n)]


def string_to_bit_array(text):
    array = list()
    for char in text:
        binval = binvalue(char, 8)
        array.extend([int(x) for x in list(binval)])
    return array


def bit_array_to_string(array):
    res = ''.join([chr(int(y, 2)) for y in [''.join([str(x) for x in bytes]) for bytes in nsplit(array, 8)]])
    return res


def string_to_ind_bit(string):
    array = list(string)
    for q in range(0, len(array)):
        array[q] = int(array[q])

    return array


def ind_bit_to_string(array):
    string = ""
    for r in range(0, len(array)):
        string = string + str(array[r])

    return string


def encrypt(blockSize, plaintextBlockList, shiftRegister):

    key       = "11001001110010011100100111001001110010011100100111001001110010011100100111001001110010011100100111001001110010011100100111001001"
    ciphertextBlockList = []
    for j in range(0, len(plaintextBlockList)):
        plaintextBlock = plaintextBlockList[j]

        tempRegister = string_to_ind_bit(aes.encryption(shiftRegister, key))
        ciphertextBlock = []

        for m in range(0, blockSize):
            ciphertextBlock.append(tempRegister[m] ^ plaintextBlock[m])

        shiftRegister = string_to_ind_bit(shiftRegister)
        for n in range(0, blockSize):
            shiftRegister.pop(0)
            shiftRegister.append(tempRegister[n])
        shiftRegister = ind_bit_to_string(shiftRegister)
        ciphertextBlockList.append(ciphertextBlock)

    return ciphertextBlockList


def decrypt_blocks(blockSize, decrypted_blocks):
    decrypted_text = []
    for k in range(0, len(decrypted_blocks)):
        for p in range(0, blockSize):
            decrypted_text.append(int(decrypted_blocks[k][p]))
    decrypted_text_string = bit_array_to_string(decrypted_text)

    return decrypted_text_string


try:
    xrange
except Exception:
    xrange = range

    def _string_to_bytes(text):
        if isinstance(text, bytes):
            return text
        return [ord(c) for c in text]

    def _bytes_to_string(binary):
        return bytes(binary)

    def _concat_list(a, b):
        return a + bytes(b)


@time_exec
def aes_ofb(plaintext, key='', show=False):
    blockSize = 16
    plaintext = string_to_bit_array(plaintext)

    for i in range(0, len(plaintext)):
        plaintext[i] = int(plaintext[i])
    plaintextBlockList = list(chunks(plaintext, blockSize))

    appendNo = len(plaintext) % blockSize
    for i in range(0, appendNo):
        plaintextBlockList[len(plaintextBlockList) - 1].append(0)

    IVsize = 128
    shiftRegister = randomIV(IVsize)

    ciphertextBlockList = encrypt(blockSize, plaintextBlockList, shiftRegister)

    if show:
        print("-----------------------------")
        print('ciphertext AES_OFB:', ciphertextBlockList)

    decryptedBlocks = encrypt(blockSize, ciphertextBlockList, shiftRegister)
    decryptedTextString = decrypt_blocks(blockSize, decryptedBlocks)

    if show:
        print('decrypted by AES_OFB:', decryptedTextString)
        print("-----------------------------\n")

