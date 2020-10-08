import re
import secrets
from collections import Counter
from itertools import chain

import numpy as np
from scipy.stats import chisquare


def xor(a, b):
    return bytes(a_byte ^ b_byte for a_byte, b_byte in zip(a, b))


def edit_distance(a, b):
    return sum([bin(byte).count("1") for byte in xor(a, b)])


def single_byte_xor(byte, byte_array):
    return xor(byte_array, byte * len(byte_array))


def single_byte_xor_breaker(ciphertext):
    def attempt_crack():
        for char in range(256):
            byte = bytes([char])
            score = text_scorer(single_byte_xor(byte, ciphertext)).score()
            yield score, byte

    return max(attempt_crack())


def repeating_key_xor(ciphertext, key):
    def nth_xor(n, byte):
        return byte ^ key[n % len(key)]

    return bytes([nth_xor(n, byte) for n, byte in enumerate(ciphertext)])


class text_scorer:
    # http://cs.wellesley.edu/~fturbak/codman/letterfreq.html
    char_frequencies = [
        ["a", 0.08167],
        ["b", 0.01492],
        ["c", 0.02782],
        ["d", 0.04253],
        ["e", 0.12702],
        ["f", 0.02228],
        ["g", 0.02015],
        ["h", 0.06094],
        ["i", 0.06966],
        ["j", 0.00153],
        ["k", 0.00772],
        ["l", 0.04025],
        ["m", 0.02406],
        ["n", 0.06749],
        ["o", 0.07507],
        ["p", 0.01929],
        ["q", 0.00095],
        ["r", 0.05987],
        ["s", 0.06327],
        ["t", 0.09056],
        ["u", 0.02758],
        ["v", 0.00978],
        ["w", 0.02360],
        ["x", 0.00150],
        ["y", 0.01974],
        ["z", 0.00074],
    ]

    expected_frequencies = [row[1] for row in char_frequencies]
    letter_char_index = list(range(65, 91)) + list(range(97, 123)) + [32]
    letter_char_index2 = list(range(97, 123))
    abnormal_char_index = list(range(0, 9)) + list(range(16, 32)) + list(
        range(127, 256))

    non_alphabet_chars = re.compile(b'[^a-zA-Z]+')
    desireable_chars = re.compile(b'''[\w\s,.'!-"\(\)\&%@#~-]''')

    def __init__(self, byte_array):
        self.byte_array = byte_array
        self.total_chars = len(byte_array)
        self.char_instances = Counter(byte_array)

    def score(self):

        # ---Prescreen---
        # check for high letter proportion
        letter_instances = self.non_alphabet_chars.sub(b'', self.byte_array)

        if (sum(letter_instances) / self.total_chars) < 0.8:
            return 0

        # check for low abnormal character proportion
        abnormal_char_instances = self.desireable_chars.sub(
            b'', self.byte_array)

        if 0.2 < (sum(abnormal_char_instances) / self.total_chars):
            return 0

        # ---Full scorer---

        # Count letter instances independent of case.
        case_independent_letters = Counter(letter_instances.lower())
        case_independent_letter_instances = [
            case_independent_letters.get(char, 0)
            for char in self.letter_char_index2
        ]

        # Normalise letter instances.
        total = sum(case_independent_letter_instances)
        case_independent_letter_frequencies = [
            a / total for a in case_independent_letter_instances
        ]

        # Return goodness of fit.
        return chisquare(case_independent_letter_frequencies,
                         self.expected_frequencies)[1]


def find_key_size(max_size, data):
    samples = 10
    normalised_edit_distance = np.zeros([samples])
    results = []

    for keysize in range(1, max_size):
        for pair in range(samples):

            # Take adjacent keysize size blocks.
            ciphertext = data[(2 * pair) * keysize:(2 * pair + 1) * keysize]
            key = data[(2 * pair + 1) * keysize:(2 * pair + 2) * keysize]

            # Calculate normalised edit distance.
            normalised_edit_distance[pair] = edit_distance(ciphertext,
                                                           key) / keysize

        # Store average edit distance for keysize.
        results.append([np.average(normalised_edit_distance), keysize])
    return [row[1] for row in sorted(results)]


def key_finder(key_size, data):

    # Create list of rectangular size using key_size.
    lower_multiple = len(data) - (len(data) % key_size)
    data_array = np.frombuffer(data, dtype="uint8")[0:lower_multiple]

    # Reshape to key_size size rows and transpose.
    data_array = data_array.reshape(-1, key_size)
    output_list = [bytes(row.tolist()) for row in data_array.T]

    # Return most promising key of key_size size.
    return b"".join([single_byte_xor_breaker(item)[1] for item in output_list])


def pad(block_size, data):
    # PKCS#7 padding.
    if (len(data) % block_size) == 0:
        data += bytes([block_size]) * block_size
    else:
        pad_size = block_size - len(data) % block_size
        data += bytes([pad_size]) * pad_size
    return data


def depad(data):
    # PKCS#7 depadding.
    pad_size = data[-1]
    if data[-pad_size:] != bytes([pad_size]) * pad_size:
        raise ValueError("Bad padding encountered!")
    return data[0:-pad_size]


def random_AES_key():
    return secrets.token_bytes(16)


def ECB_mode_check(data):
    array = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(array) - len(np.unique(array, axis=0))
    return True if 0 < duplicate_blocks else False
