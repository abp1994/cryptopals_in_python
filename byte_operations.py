import secrets
import numpy as np
import multiprocessing as mp
from collections import Counter
from scipy.stats import chisquare


def xor(a, b):
    return bytes(a_byte ^ b_byte for a_byte, b_byte in zip(a, b))


def edit_distance(a, b):
    return sum([bin(byte).count("1") for byte in xor(a, b)])


def single_byte_xor(byte, byte_array):
    return xor(byte_array, byte * len(byte_array))


def attempt_crack(char, ciphertext):

    byte = bytes([char])
    print(byte)
    score = text_scorer(single_byte_xor(byte, ciphertext))
    return score, byte


def single_byte_xor_breaker(ciphertext):
    pool = mp.Pool(mp.cpu_count())
    results = []
    results = pool.starmap_async(attempt_crack,
                                 [(char, ciphertext)
                                  for char in range(256)]).get()
    pool.close()
    print(max(results))
    return max(results)


def single_byte_xor_breaker2(ciphertext):
    def attempt_crack():
        for char in range(256):
            byte = bytes([char])
            score = text_scorer(single_byte_xor(byte, ciphertext))
            yield score, byte

    return max(attempt_crack())


def repeating_key_xor(ciphertext, key):
    def nth_xor(n, byte):
        return byte ^ key[n % len(key)]

    return bytes([nth_xor(n, byte) for n, byte in enumerate(ciphertext)])


def text_scorer(byte_array):

    # ---Prescreen---
    letter_count = 0
    abnormal_char_count = 0
    for char in byte_array:
        # Count alphabet characters.
        if 64 < char < 91 or 96 < char < 123 or char == 32:
            letter_count += 1

        # Count abnormal chars (not including tab type chars).
        if not (8 < char < 16 or 31 < char < 127):
            abnormal_char_count += 1

    letter_proportion = letter_count / len(byte_array)
    abnormal_char_proportion = abnormal_char_count / len(byte_array)

    # Check string is of low punctuation proportion.
    if letter_proportion < 0.8:
        return 0

    # Check string is of low abnormal character proportion.
    if 0.2 < abnormal_char_proportion:
        return 0

    # ---Full scorer---
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
    observed_frequencies = np.zeros(26)

    # Make bytearray of only lowercase letters (lowerify uppercase letters).
    alphabet_bytes = bytearray()
    for byte in byte_array:
        if 96 < byte < 123:
            alphabet_bytes.append(byte)
        elif 64 < byte < 91:
            alphabet_bytes.append(byte + 22)

    # Count alphabet character frequencies.
    char_instances = list(Counter(alphabet_bytes).items())

    for char, frequency in char_instances:
        observed_frequencies[char - 97] = frequency

    # Normalise observed_frequencies.
    observed_frequencies = observed_frequencies / np.sum(observed_frequencies)

    # Return goodness of fit.
    return chisquare(observed_frequencies, expected_frequencies)[1]


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
