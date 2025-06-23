import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).parents[2].resolve()))
import cryptopals.cryptopals as c


class TestCryptopals_set1(unittest.TestCase):

    def test_C1(self):
        self.assertEqual(
            c.Set1.challenge_1(),
            bytearray("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa",
                      "WtlIGEgcG9pc29ub3VzIG11c2hyb29t"))

    def test_C2(self):
        self.assertEqual(c.Set1.challenge_2(),
                         "746865206b696420646f6e277420706c6179")

    def test_C5(self):
        self.assertEqual(
            c.Set1.challenge_5(),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d6"
            "3343c2a26226324272765272a282b2f20430a652e2c652a3124"
            "333a653e2b2027630c692b20283165286326302e27282f",
        )


class TestCryptopals_set2(unittest.TestCase):

    def test_C9(self):
        self.assertEqual(c.Set2.challenge_9(),
                         b"YELLOW SUBMARINE\x04\x04\x04\x04")

    def test_C13(self):
        self.assertEqual(c.Set2.challenge_13()["role"], "admin")


if __name__ == "__main__":
    unittest.main()
