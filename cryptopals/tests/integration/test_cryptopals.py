import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).parents[2].resolve()))
import cryptopals


class TestCryptopals(unittest.TestCase):
    def test_C1(self):
        pass


if __name__ == "__main__":
    unittest.main()
