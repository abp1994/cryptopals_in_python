import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).parents[2].resolve()))
import utils as ut


class TestUtils(unittest.TestCase):

    def test_encode(self):
        self.assertEqual(ut.encode("Hello World"),
                         "Hello World".encode("utf-8"))

    def test_decode(self):
        encoded_string = "Hello World".encode("utf-8")
        self.assertEqual(ut.decode(encoded_string),
                         encoded_string.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
