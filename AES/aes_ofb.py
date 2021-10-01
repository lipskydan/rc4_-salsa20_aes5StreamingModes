# import numpy as np
import random  # To randomize Initial Vector
import aes


# Split string into blocks (string, block size)
def chunks(string, blockSize):
    # For item i in a range that is a length of l,
    for i in range(0, len(string), blockSize):
        # Create an index range for l of n items:
        yield string[i:i + blockSize]


# Generate random initial vector
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


def binvalue(val, bitsize):  # Return the binary value as a string of the given size
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise ("binary value larger than the expected size")
    while len(binval) < bitsize:
        binval = "0" + binval  # Add as many 0 as needed to get the wanted size
    return binval


def nsplit(s, n):  # Split a list into sublists of size "n"
    return [s[k:k + n] for k in xrange(0, len(s), n)]


def string_to_bit_array(text):  # Convert a string into a list of bits
    array = list()
    for char in text:
        binval = binvalue(char, 8)  # Get the char value on one byte
        array.extend([int(x) for x in list(binval)])  # Add the bits to the final list
    return array


def bit_array_to_string(array):  # Recreate the string from the bit array
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
    # plaintextBlock = [None] * blockSize
    ciphertextBlockList = []
    for j in range(0, len(plaintextBlockList)):
        plaintextBlock = plaintextBlockList[j]
        # tempRegister = string_to_ind_bit(shiftRegister)
        tempRegister = string_to_ind_bit(aes.encryption(shiftRegister, key))
        ciphertextBlock = []
        # Get the first r bits, then XOR with plaintext, and append to ciphertextblock
        for m in range(0, blockSize):
            ciphertextBlock.append(tempRegister[m] ^ plaintextBlock[m])
        # Shift the bits to the left, then add temp register bits
        shiftRegister = string_to_ind_bit(shiftRegister)
        for n in range(0, blockSize):
            shiftRegister.pop(0)
            shiftRegister.append(tempRegister[n])
        shiftRegister = ind_bit_to_string(shiftRegister)
        ciphertextBlockList.append(ciphertextBlock)

    return ciphertextBlockList




def decrypt_blocks(decrypted_blocks):
    decrypted_text = []
    for k in range(0, len(decrypted_blocks)):
        for p in range(0, blockSize):
            decrypted_text.append(int(decrypted_blocks[k][p]))
    decrypted_text_string = bit_array_to_string(decrypted_text)

    return decrypted_text_string


# Python 3 compatibility
try:
    xrange
except Exception:
    xrange = range

    # Python 3 supports bytes, which is already an array of integers
    def _string_to_bytes(text):
        if isinstance(text, bytes):
            return text
        return [ord(c) for c in text]

    # In Python 3, we return bytes
    def _bytes_to_string(binary):
        return bytes(binary)

    # Python 3 cannot concatenate a list onto a bytes, so we bytes-ify it first
    def _concat_list(a, b):
        return a + bytes(b)


def run(plaintext, show=False):
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
    decryptedTextString = decrypt_blocks(decryptedBlocks)

    if show:
        print('decrypted by AES_OFB:', decryptedTextString)
        print("-----------------------------\n")

