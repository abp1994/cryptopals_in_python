import os
import re
import secrets
import time
import numpy as np
import base64 as b64
from collections import Counter
from scipy.stats import chisquare
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def import_data(file_name):
    file_path = os.path.join(os.path.dirname(__file__), file_name)
    with open(file_path) as f:
        return f.read()


def encode(text):
    return text.encode("utf-8")


def decode(byte_array):
    return byte_array.decode("utf-8")


def bytes_xor(a, b):
    return bytes(a_byte ^ b_byte for a_byte, b_byte in zip(a, b))


def single_byte_xor(byte, byte_array):
    return bytes_xor(byte_array, byte * len(byte_array))


def single_byte_xor_breaker(byte_array):
    def attempt_crack():
        for char in range(256):
            byte = bytes([char])
            score = text_scorer(single_byte_xor(byte, byte_array))
            yield score, byte

    return max(attempt_crack())


def repeating_key_xor(cipher, key):
    def ith_xor(i, byte):
        return byte ^ key[i % len(key)]

    return bytes([ith_xor(i, byte) for i, byte in enumerate(cipher)])


def edit_distance(b1, b2):
    tally = [bin(byte).count("1") for byte in bytes_xor(b1, b2)]
    return sum(tally)


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
    if letter_proportion < 0.8: return 0

    # Check string is of low abnormal character proportion.
    if 0.2 < abnormal_char_proportion: return 0

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
        if 96 < byte < 123: alphabet_bytes.append(byte)
        elif 64 < byte < 91: alphabet_bytes.append(byte + 22)

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
            cipher = data[(2 * pair) * keysize:(2 * pair + 1) * keysize]
            key = data[(2 * pair + 1) * keysize:(2 * pair + 2) * keysize]

            # Calculate normalised edit distance.
            normalised_edit_distance[pair] = edit_distance(cipher,
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


def pad(block_size, data, multiples_allowed):
    # PKCS#7 padding.
    if multiples_allowed == True:
        if (len(data) % block_size) != 0:
            pad_size = block_size - len(data) % block_size
            data += bytes([pad_size]) * pad_size
        else:
            data += bytes([block_size]) * block_size
    else:
        difference = block_size - len(data)
        data += bytes([difference]) * difference
    return data


def depad(data):
    # PKCS#7 depadding.
    pad_size = data[-1]
    if data[-pad_size:] != bytes([pad_size]) * pad_size:
        raise Exception("Bad padding encountered")
    return data[0:-pad_size]


class ECB_new:
    def encrypt(self, key, data):
        cipher = Cipher(algorithms.AES(key),
                        modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, key, data):
        cipher = Cipher(algorithms.AES(key),
                        modes.ECB(),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()


def ECB(mode, key, data):
    cipher = Cipher(algorithms.AES(key),
                    modes.ECB(),
                    backend=default_backend())
    if mode == "encrypt":
        encryptor = cipher.encryptor()
        result = encryptor.update(data) + encryptor.finalize()
    else:
        decryptor = cipher.decryptor()
        result = decryptor.update(data) + decryptor.finalize()
    return result


def CBC(mode, iv, key, data):
    iv = bytes([0]) * 16 if iv == b"" else iv
    input_message = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
    output_message = b""
    if mode == "encrypt":
        for block in input_message:
            step_1 = bytes_xor(iv, block)
            iv = ECB("encrypt", key, step_1)
            output_message += iv
    else:
        for block in input_message:
            step_1 = ECB("decrypt", key, block)
            output_message += bytes_xor(iv, step_1)
            iv = block
    return (output_message)


def random_AES_key():
    return secrets.token_bytes(16)


def profile_for(email):
    profile = parse_profile(email)
    data = pad(16, profile, multiples_allowed=True)
    encrypted_user_data = ECB("encrypt", b"PASSWORDPASSWORD", data)
    return encrypted_user_data


def profile_decrypt(data):
    decrypted_user_data = ECB("decrypt", b"PASSWORDPASSWORD", data)
    return decrypted_user_data


def unpack_profile(data):
    return {
        decode(key): decode(value)
        for key, value in (line.split(b"=") for line in data.split(b"&"))
    }


def parse_profile(email):
    if 0 < email.count("=") + email.count("&"):
        raise Exception("Invalid character encountered")
    return encode(f"email={email}&uid=10&role=user")


class ECB_oracle_C11:
    def encrypt(self, data):
        data = secrets.token_bytes(
            secrets.randbelow(5)) + data + secrets.token_bytes(
                secrets.randbelow(5))
        data_p = pad(16, data, multiples_allowed=True)
        if secrets.choice([True, False]):
            mode = "ECB"
            result = ECB_new().encrypt(random_AES_key(), data_p)
        else:
            mode = "CBC"
            result = CBC("encrypt", secrets.token_bytes(16), random_AES_key(),
                         data_p)
        return result, mode


class ECB_oracle_C12:
    def __init__(self):
        self.key = secrets.token_bytes(16)
        self.secret = b64.b64decode(import_data("data_S2C12.txt"))

    def encrypt(self, bytes_to_prepend):
        data = pad(16, bytes_to_prepend + self.secret, multiples_allowed=True)
        return ECB_new().encrypt(self.key, data)


def ECB_mode_check(data):
    array = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(array) - len(np.unique(array, axis=0))
    return True if 0 < duplicate_blocks else False


def ECB_mode_check_2(oracle):
    data = oracle.encrypt(b"0" * 50)
    blocks = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(blocks) - len(np.unique(blocks, axis=0))
    return True if 0 < duplicate_blocks else False


def find_block_size(oracle):
    # Encrypt increasingly long byte strings until output changes size.
    # Record change in size of output.
    initial_output_size = len(oracle.encrypt(b""))
    output_size = initial_output_size
    bytestring = b""
    while output_size == initial_output_size:
        bytestring += b"0"
        output_size = len(oracle.encrypt(bytestring))
        if 100 < len(bytestring):
            raise Exception("Indeterminable block size")
    return output_size - initial_output_size


class set_1:
    def challenge_1(self):
        print("\n-- Challenge 1 - Convert hex to base 64 --")

        hex_ciphertext = (
            "49276d206b696c6c696e6720796f757220627261696e206c696b65"
            "206120706f69736f6e6f7573206d757368726f6f6d")
        data = bytes.fromhex(hex_ciphertext)
        B64_encode = b64.b64encode(data)

        print(f"Hex ciphertext : {hex_ciphertext}")
        print(f"Plaintext      : {decode(data)}")
        print(f"Base 64 encode : {decode(B64_encode)}")

    def challenge_2(self):
        # Take two equal-size buffers and produce their XOR combination.
        print("\n-- Challenge 2 - Fixed XOR --")

        hex_ciphertext = "1c0111001f010100061a024b53535009181c"
        hex_key = "686974207468652062756c6c277320657965"
        data = bytes.fromhex(hex_ciphertext)
        key = bytes.fromhex(hex_key)
        decrypted_data = bytes_xor(data, key)

        print(f"Hex ciphertext          : {hex_ciphertext}")
        print(f"Hex key                 : {hex_key}")
        print(f"XOR decrypted plaintext : {decode(decrypted_data)}")
        print(f"Hex encode              : {decrypted_data.hex()}")

    def challenge_3(self):
        print("\n-- Challenge 3 - Single-byte XOR cipher --")

        hex_ciphertext = (
            "1b37373331363f78151b7f2b783431333d78397828372d363c7837"
            "3e783a393b3736")
        data = bytes.fromhex(hex_ciphertext)
        score, byte = single_byte_xor_breaker(data)
        plaintext = single_byte_xor(byte, data)

        print(f"Hex ciphertext                   : {hex_ciphertext}")
        print(f"Highest frequency analysis score : {score}")
        print(f"Corresponding Key                : {decode(byte)}")
        print(f"Decrypted plaintext              : {decode(plaintext)}")

    def challenge_4(self):
        print("\n-- Challenge 4 - Detect single-char XOR --")

        file_name = "data_S1C4.txt"
        hex_ciphertext = import_data(file_name)

        def text_breaker():
            for line_index, line in enumerate(hex_ciphertext.splitlines()):
                data = bytes.fromhex(line)
                score, byte = single_byte_xor_breaker(data)
                yield score, byte, line_index, data

        score, byte, line_index, data = max(text_breaker())
        plaintext = single_byte_xor(byte, data)

        print(f"Hex data file                    : {file_name}")
        print(f"Highest frequency analysis score : {score}")
        print(f"Corresponding line               : {line_index}")
        print(f"Corresponding key                : {decode(byte)}")
        print(f"Decrypted plaintext              : {decode(plaintext)}")

    def challenge_5(self):
        print("\n-- Challenge 5 - Implement repeating-key XOR --")

        stanza = ("Burning 'em, if you ain't quick and nimble\n"
                  "I go crazy when I hear a cymbal")
        key = encode("ICE")
        data = encode(stanza)
        cyphertext = repeating_key_xor(data, key)

        print(f"Key                                : {key}")
        print(f"Plaintext                          : \n{stanza}")
        print(f"Repeating key encrypt (hex encode) : {cyphertext.hex()}")

    def challenge_6(self):
        print(f"\n-- Challenge 6 - Break repeating-key XOR --")
        print(f"-- Part 1 --")

        data_1 = encode("this is a test")
        data_2 = encode("wokka wokka!!!")

        print(f"String 1      : {decode(data_1)}")
        print(f"String 2      : {decode(data_2)}")
        print(f"Edit distance : {edit_distance(data_1, data_2)}")
        print(f"-- Part 2 --")

        B64_ciphertext = import_data("data_S1C6.txt")
        data = b64.b64decode(B64_ciphertext)
        likely_key_sizes = find_key_size(40, data)

        # Find most likely key.
        def key_comparison():
            for key_size in likely_key_sizes[0:3]:
                key = key_finder(key_size, data)
                secret = repeating_key_xor(data, key)
                score = text_scorer(secret)
                yield score, key, secret

        score, key, secret = max(key_comparison())

        print(f"Most likely key sizes : {likely_key_sizes[0:3]}")
        print(f"Highest score         : {score}")
        print(f"Corresponding Key     : {decode(key)}")
        print(f"Secret                : \n{decode(secret[:90])}...")

    def challenge_7(self):
        print(f"\n-- Challenge 7 - AES in ECB mode --")

        key = encode("YELLOW SUBMARINE")
        data = b64.b64decode(import_data("data_S1C7.txt"))
        plaintext = ECB_new().decrypt(key, data)

        print(f"Key    : {decode(key)}")
        print(f"Secret : \n{decode(plaintext[:90])}...")

    def challenge_8(self):
        print(f"\n-- Challenge 8 - Detect AES in ECB mode --")
        print(f"-- Method 1 --")

        hex_ciphertext = import_data("data_S1C8.txt")

        def text_breaker():
            for line_index, line in enumerate(hex_ciphertext.splitlines()):
                data = bytes.fromhex(line)
                unique_char_instances = len(list(Counter(data).items()))
                yield unique_char_instances, line_index

        unique_char_instances, line_index = min(text_breaker())
        print(
            f"Assume ECB 1:1 mapping has low diversity of characters compared"
            " to random data")
        print(f"Lowest number of unique chars : {unique_char_instances}")
        print(f"Corresponding line            : {line_index}")
        print(f"-- Method 2 --")

        # Find if data contains duplicate lines.
        for line_index2, line in enumerate(hex_ciphertext.splitlines()):
            if ECB_mode_check(bytes.fromhex(line)): break

        print(f"Find line with duplicate blocks")
        print(f"Corresponding line            : {line_index2}")


class set_2:
    def challenge_9(self):
        print(f"\n-- Challenge 9 - Implement PKCS#7 padding --")

        data = encode("YELLOW SUBMARINE")
        size = 20
        print(f"{data} padded to {size} bytes using PKCS#7 : "
              f"{pad(size, data, multiples_allowed=False)}")

    def challenge_10(self):
        print(f"\n-- Challenge 10 - Implement CBC mode --")

        data_p = pad(16,
                     b"This is a secret message! TOP SECRET",
                     multiples_allowed=True)
        key = pad(16, b"PASSWORD", multiples_allowed=False)
        iv = pad(16, b"12345", multiples_allowed=False)

        ECB_cyphertext = ECB_new().encrypt(key, data_p)
        ECB_plaintext = depad(ECB_new().decrypt(key, ECB_cyphertext))
        CBC_cyphertext = CBC("encrypt", iv, key, data_p)
        CBC_plaintext = depad(CBC("decrypt", iv, key, CBC_cyphertext))

        print(f"Padded Secret Message : {data_p}")
        print(f"Key                   : {key}")
        print(f"ECB encrypted message : {ECB_cyphertext}")
        print(f"ECB decrypted message : {ECB_plaintext}")
        print(f"iv                    : {iv}")
        print(f"CBC encrypted message : {CBC_cyphertext}")
        print(f"CBC decrypted message : {CBC_plaintext}")
        print("----- Part 2 ------")

        data = b64.b64decode(import_data("data_S2C10.txt"))
        key = b"YELLOW SUBMARINE"
        iv = bytes([0]) * 16

        decrypted = decode(depad(CBC("decrypt", iv, key, data)))
        print(f"CBC decrypted message : \n{decrypted[0:90]}...")

    def challenge_11(self):
        print(f"\n-- Challenge 11 - An ECB/CBC detection oracle --")

        oracle = ECB_oracle_C11()
        encryption, mode = oracle.encrypt(b"0" * 100)

        print(f"Random AES Key generator    : {random_AES_key()}")
        print(f"Oracle encryption mode used : {mode}")
        print(f"ECB encrypted data?         : {ECB_mode_check(encryption)}")

    def challenge_12(self):
        print(f"\n-- Challenge 12 - "
              "Byte-at-a-time ECB decryption (Simple) --")

        oracle = ECB_oracle_C12()
        block_size = find_block_size(oracle)

        print(f"Determined oracle block size : {block_size}")
        print(f"Oracle using ECB mode?       : {ECB_mode_check_2(oracle)}")

        decryption = b""
        data_size = len(oracle.encrypt(b""))

        # For all blocks in the data.
        for block_position in range(0, data_size, block_size):
            block_start = block_position
            block_end = block_position + block_size

            # For all byte positions along the block (15->0).
            for byte_position in reversed(range(block_size)):
                buffer = b"0" * byte_position + decryption
                model_bytes = oracle.encrypt(
                    b"0" * (byte_position))[block_start:block_end]

                # test all possible characters against model_byte
                for char in range(256):
                    byte = bytes([char])
                    if model_bytes == oracle.encrypt(
                            buffer + byte)[block_start:block_end]:
                        decryption += byte
                        break

        print(f"Decoded message : \n{decode(depad(decryption))}")

    def challenge_13(self):
        print(f"\n-- Challenge 13 - ECB cut-and-paste --")
        print(f"-- Part 1 --")

        text = """foo=bar&baz=qux&zap=zazzle"""
        email = "hello@world.com"
        parsed = parse_profile(email)

        print(f"Example string   : {text}")
        print(f"Unpacked profile : {unpack_profile(encode(text))}")
        print(f"Example Email    : {email}")
        print(f"Parsed profile   : {parsed}")
        print(f"Unpacked profile : {unpack_profile(parsed)}")
        print(f"-- Part 2 --")

        base_email = "user@hack.com"
        base_encryption = profile_for(base_email)
        base_encryption_len = len(base_encryption)
        base_decryption = profile_decrypt(base_encryption)

        print(f"Base email        : {base_email}")
        print(f"Encrypted profile : {base_encryption}")
        print(f"Encrypted size  : {base_encryption_len}")
        print(f"Decrypted data    : {base_decryption}")

        # Create an email that creates a whole new block in output.
        end_align_email = base_email
        end_align_encryption = base_encryption
        while len(end_align_encryption) == base_encryption_len:
            end_align_email = "a" + end_align_email
            end_align_encryption = profile_for(end_align_email)
        end_align_encryption_len = len(end_align_encryption)

        print(f"End aligning email : {end_align_email}")
        print(f"Encrypted profile  : {end_align_encryption}")
        print(f"Encrypted size   : {end_align_encryption_len}")

        # Add bytes to push unwanted data from encryption into end block and crop useful blocks.
        bytes_to_remove = len(b"user")
        crop_email = ("b" * bytes_to_remove) + end_align_email
        crop = profile_for(crop_email)[0:48]
        decryption = profile_decrypt(crop)

        print(f"bytes to push into new block : {bytes_to_remove}")
        print(f"Crop aligning email          : {crop_email}")
        print(f"Encrypted profile crop       : {crop}")
        print(f"Crop size                  : {len(crop)}")
        print(f"Decrypted crop               : {decryption}")

        # Create an email that shows its position in the encryption.
        position_email = base_email
        # Look for two identical blocks in encryption.
        while not ECB_mode_check(profile_for(position_email)):
            position_email = "c" + position_email

        print(f"Position finding email : {position_email}")

        # Find position at which duplicated block starts changing.
        position = 0
        while ECB_mode_check(profile_for(position_email)):
            position_email_list = list(position_email)
            position_email_list[position] = "d"
            position_email = "".join(position_email_list)
            position += 1
        position -= 1

        print(f"Position finding email  : {position_email}")
        print(f"Position of block start : {position}")

        bytes_to_add = position - len(base_email)
        if bytes_to_add < 0: bytes_to_add += 16
        block_end_email = ("e" * bytes_to_add) + base_email

        print(f"Bytes to add to email : {bytes_to_add}")
        print(f"Email ending block    : {block_end_email}")

        # Craft new ending for encrypted data.
        new_end = decode(pad(16, b"admin", multiples_allowed=True))
        new_end_encryption_email = block_end_email + new_end
        cut = profile_for(new_end_encryption_email)[32:48]
        decrypted_cut = profile_decrypt(cut)

        print(f"new end encrypting email : {new_end_encryption_email}")
        print(f"new ending encryption    : {cut}")
        print(f"new ending decrypted     : {decrypted_cut}")

        attacker_encrypted_profile = crop + cut
        attacker_decrypted_profile = profile_decrypt(
            attacker_encrypted_profile)
        attacker_profile = unpack_profile(depad(attacker_decrypted_profile))

        print(f"Attacker encrypted profile : {attacker_encrypted_profile}")
        print(f"Attacker decrypted profile : {attacker_decrypted_profile}")
        print(f"Attacker  profile          : {attacker_profile}")

    def challenge_14(self):
        print(f"\n-- Challenge 14 - Byte-at-a-time ECB decryption (Harder) --")
        # Find bytes needed to align end of blocks.

    def challenge_15(self):
        print(f"\n-- Challenge 15 - PKCS#7 padding validation --")

        a = b"ICE ICE BABY\x04\x04\x04\x04"
        b = b"ICE ICE BABY\x05\x05\x05\x05"
        c = b"ICE ICE BABY\x01\x02\x03\x04"

        for i in [a, b, c]:
            try:
                print(f"Depad of {i} : {depad(i)}")
            except Exception as e:
                print(f"Depad of {i} : {e}")


def main():
    print("\n\n-- The Cryptopals Crypto Challenges in Python by Akaash BP --")
    # https://cryptopals.com
    startTime = time.time()

    set_1().challenge_1()
    set_1().challenge_2()
    set_1().challenge_3()
    set_1().challenge_4()
    set_1().challenge_5()
    set_1().challenge_6()
    set_1().challenge_7()
    set_1().challenge_8()

    set_2().challenge_9()
    set_2().challenge_10()
    set_2().challenge_11()
    set_2().challenge_12()
    set_2().challenge_13()
    set_2().challenge_14()
    set_2().challenge_15()

    executionTime = (time.time() - startTime)
    print('\nExecution time in seconds: ' + str(executionTime))


if __name__ == "__main__":
    main()
