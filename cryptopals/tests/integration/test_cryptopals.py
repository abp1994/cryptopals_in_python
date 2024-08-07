import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).parents[2].resolve()))
import utils as ut

import cryptopals.cryptopals as c


class TestCryptopals_set1(unittest.TestCase):
    def test_C1(self):
        self.assertEqual(
            c.Set1.challenge_1(),
            b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        )

    def test_C2(self):
        self.assertEqual(c.Set1.challenge_2(), "746865206b696420646f6e277420706c6179")

    def test_C3(self):
        self.assertEqual(c.Set1.challenge_3(), b"Cooking MC's like a pound of bacon")

    def test_C4(self):
        result = c.Set1.challenge_4()
        self.assertEqual(result["key"], b"5")
        self.assertEqual(result["line_index"], 170)
        self.assertEqual(result["plaintext"], b"Now that the party is jumping\n")

    def test_C5(self):
        self.assertEqual(
            c.Set1.challenge_5(),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d6"
            "3343c2a26226324272765272a282b2f20430a652e2c652a3124"
            "333a653e2b2027630c692b20283165286326302e27282f",
        )

    def test_C6(self):
        result = c.Set1.challenge_6()
        secret = ut.import_data("Play_That_Funky_Music_Snippet.txt")

        self.assertEqual(result["key"], b"Terminator X: Bring the noise")
        self.assertEqual(result["secret"], secret)

    def test_C7(self):
        secret = ut.import_data("Play_That_Funky_Music_Snippet.txt")
        self.assertEqual(c.Set1.challenge_7(), secret)

    def test_C8(self):
        self.assertEqual(c.Set1.challenge_8(), 132)


class TestCryptopals_set2(unittest.TestCase):
    def test_C9(self):
        self.assertEqual(c.Set2.challenge_9(), b"YELLOW SUBMARINE\x04\x04\x04\x04")

    def test_C10(self):
        secret = ut.import_data("Play_That_Funky_Music_Snippet.txt")
        self.assertEqual(c.Set2.challenge_10(), secret)

    def test_C11(self):
        result = c.Set2.challenge_11()
        for mode, detected_mode in zip(result["modes"], result["detected_modes"]):
            self.assertEqual(mode, detected_mode)

    def test_C12(self):
        secret = ut.import_data("Ice_Ice_Baby_Snippet.txt")
        self.assertEqual(c.Set2.challenge_12(), secret)

    def test_C13(self):
        self.assertEqual(c.Set2.challenge_13()["role"], "admin")

    def test_C14(self):
        secret = ut.import_data("Ice_Ice_Baby_Snippet.txt")
        self.assertEqual(c.Set2.challenge_14(), secret)

    def test_C15(self):
        pass

    def test_C16(self):
        self.assertTrue(c.Set2.challenge_16())


class TestCryptopals_set3(unittest.TestCase):
    def test_C17(self):
        self.assertTrue(c.Set3.challenge_17())


if __name__ == "__main__":
    unittest.main()
