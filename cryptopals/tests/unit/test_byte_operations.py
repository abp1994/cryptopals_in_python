import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).parents[2].resolve()))
import byte_operations as bo


class Testbyte_operations(unittest.TestCase):
    def test_xor(self):
        self.assertEqual(bo.xor(b'abcde', b'abcde'), b'\x00\x00\x00\x00\x00')
        self.assertEqual(bo.xor(b'\x00\x01\x01', b'\x00\x00\x01'),
                         b'\x00\x01\x00')

    def test_edit_distance(self):

        self.assertEqual(bo.edit_distance(b'\x00', b'\x00'), 0)
        self.assertEqual(bo.edit_distance(b'\x00', b'\x01'), 1)

        self.assertEqual(bo.edit_distance(b'cat', b'cat'), 0)
        self.assertEqual(bo.edit_distance(b'cat', b'car'), 2)
        self.assertEqual(bo.edit_distance(b'cat', b'tac'), 8)

        self.assertEqual(
            bo.edit_distance(b'this is a test', b'this is a test'), 0)
        self.assertEqual(bo.edit_distance(b'this ', b'that'), 4)
        self.assertEqual(
            bo.edit_distance(b'this is a test', b'wokka wokka!!!'), 37)

    def test_single_byte_xor(self):

        self.assertEqual(bo.single_byte_xor(b'\x00', b'\x00'), b'\x00')
        self.assertEqual(bo.single_byte_xor(b'\x01', b'\x01'), b'\x00')
        self.assertEqual(bo.single_byte_xor(b'\x00', b'\x01'), b'\x01')
        self.assertEqual(bo.single_byte_xor(b'\x01', b'\x00'), b'\x01')


if __name__ == "__main__":
    unittest.main()
