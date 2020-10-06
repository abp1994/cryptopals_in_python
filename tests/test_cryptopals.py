import os
import sys
import unittest

#sys.path.append(os.path.abspath(os.path.join('..', 'cryptopals')))
import ..cryptopals


class TestCryptopals(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(c.encode('Hello World'),
                         'Hello World'.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
