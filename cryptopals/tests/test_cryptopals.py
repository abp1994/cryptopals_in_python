import os
import sys
import unittest

sys.path.append(os.path.abspath('cryptopals'))
import cryptopals as c


class TestCryptopals(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(c.encode('Hello World'),
                         'Hello World'.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
