import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).parents[2].resolve()))
import cryptopals as c


class TestCryptopals(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(c.encode('Hello World'),
                         'Hello World'.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
