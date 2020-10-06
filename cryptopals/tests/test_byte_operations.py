import os
import sys
import unittest

sys.path.append(os.path.abspath('cryptopals'))
import byte_operations as bo


class Testbyte_operations(unittest.TestCase):
    def test_xor(self):
        self.assertEqual(bo.xor(b'abcde', b'abcde'), b'\x00\x00\x00\x00\x00')

    def test_edit_distance(self):
        self.assertEqual(
            bo.edit_distance(b'this is a test', b'wokka wokka!!!'), 37)


if __name__ == "__main__":
    unittest.main()
