import unittest
from asyncio import sleep

import rc4
import os


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


if __name__ == '__main__':
    unittest.main()
