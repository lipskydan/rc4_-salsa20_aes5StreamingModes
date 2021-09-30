import unittest
from Salsa20 import salsa20
from RC4 import rc4
from AES import aes_ctr as aes_logic


class MY_TESTS(unittest.TestCase):
    @staticmethod
    def test_1_rc4():
        assert (rc4.encrypt('Key', 'Plaintext')) == 'BBF316E8D940AF0AD3'
        assert (rc4.decrypt('Key', 'BBF316E8D940AF0AD3')) == 'Plaintext'

    @staticmethod
    def test_2_rc4():
        assert (rc4.encrypt('Wiki', 'pedia')) == '1021BF0420'
        assert (rc4.decrypt('Wiki', '1021BF0420')) == 'pedia'

    @staticmethod
    def test_3_rc4():
        assert (rc4.encrypt('Secret',
                            'Attack at dawn')) == '45A01F645FC35B383552544B9BF5'
        assert (rc4.decrypt('Secret',
                            '45A01F645FC35B383552544B9BF5')) == 'Attack at dawn'

    @staticmethod
    def test_4_salsa20_quarterround():
        tmp = [0x00000001, 0x00000000, 0x00000000, 0x00000000]
        assert salsa20.quarterround(tmp) == [0x08008145, 0x00000080, 0x00010200, 0x20500000]

    @staticmethod
    def test_5_salsa20_rowround():
        tmp = [0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
               0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
               0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
               0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a]

        assert salsa20.rowround(tmp) == [0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
                                         0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
                                         0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
                                         0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d]

    @staticmethod
    def test_6_salsa20_columnround():
        tmp = [0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
               0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
               0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
               0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a]

        assert salsa20.columnround(tmp) == [0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
                                            0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
                                            0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
                                            0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8]

    @staticmethod
    def test_7_salsa20_littleendian():
        assert salsa20.littleendian([86, 75, 30, 9]) == 0x091e4b56
        assert salsa20.littleendian([255, 255, 255, 250]) == 0xfaffffff

    @staticmethod
    def test_7_salsa20_hash():
        tmp = [211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136,
               49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207,
               31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36,
               79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54]

        assert salsa20.salsa_20_hash(tmp) == [109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170,
                                              154,
                                              29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57,
                                              118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114,
                                              219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202]

    @staticmethod
    def test_8_salsa20():
        k = bytearray(range(1, 33))
        n = bytearray([3, 1, 4, 1, 5, 9, 2, 6])
        m = 'This is message to be encrypted'

        eq = b":\xd4\xd4\xccV\x95\xbfD\xc6`'X\x8f\xed\x02\xeb\xb6\xe0\x82\x83$\xdb\x8a\xd5Y]\xe2Rml\xac"
        assert salsa20.salsa20(m.encode('UTF-8'), n, k) == eq

    @staticmethod
    def test_9_aes():
        plaintext = "Hello World!!!!!"

        iv = b'initializationVe'
        key = b'This_key_for_dem'

        aes = aes_logic.AES(key, iv)

        assert aes.decrypt_ctr(aes.encrypt_ctr(plaintext)) == plaintext


if __name__ == '__main__':
    unittest.main()
