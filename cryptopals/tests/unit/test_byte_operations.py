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
        self.assertEqual(bo.edit_distance(b'this thing', b'that thing'), 4)
        self.assertEqual(
            bo.edit_distance(b'this is a test', b'wokka wokka!!!'), 37)

    def test_single_byte_xor(self):

        self.assertEqual(bo.single_byte_xor(b'\x00', b'\x00'), b'\x00')
        self.assertEqual(bo.single_byte_xor(b'\x01', b'\x01'), b'\x00')
        self.assertEqual(bo.single_byte_xor(b'\x00', b'\x01'), b'\x01')
        self.assertEqual(bo.single_byte_xor(b'\x01', b'\x00'), b'\x01')

    def test_pad(self):

        self.assertEqual(bo.pad(3, b''), b'\x03\x03\x03')
        self.assertEqual(bo.pad(2, b'test'), b'test\x02\x02')
        self.assertEqual(bo.pad(4, b'test'), b'test\x04\x04\x04\x04')
        self.assertEqual(bo.pad(10, b'test'), b'test\x06\x06\x06\x06\x06\x06')

    def test_depad(self):

        self.assertEqual(bo.depad(b'\x03\x03\x03'), b'')
        self.assertEqual(bo.depad(b'test\x02\x02'), b'test')
        self.assertEqual(bo.depad(b'test\x04\x04\x04\x04'), b'test')
        self.assertEqual(bo.depad(b'test\x06\x06\x06\x06\x06\x06'), b'test')
        self.assertEqual(bo.depad(b'test\x02\x02\x02'), b'test\x02')

        self.assertRaises(IndexError, bo.depad, b'')
        self.assertRaises(ValueError, bo.depad, b'test')
        self.assertRaises(ValueError, bo.depad, b'test\x02')
        self.assertRaises(ValueError, bo.depad, b'test\x01\x02')
        self.assertRaises(ValueError, bo.depad, b'test\x02\x03')
        self.assertRaises(ValueError, bo.depad, b'test\x03\x02')

    def test_random_AES_key(self):

        self.assertEqual(len(bo.random_AES_key()), 16)


if __name__ == "__main__":
    unittest.main()
