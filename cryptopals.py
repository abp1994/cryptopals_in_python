import os
import re
import time
import numpy as np
import base64 as b64
from collections import Counter
from scipy.stats import chisquare
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import json


def import_data(file_name):
    file_path = os.path.join(os.path.dirname(__file__), file_name)
    with open(file_path) as f:
        return f.read()


def encode(text):
    return text.encode("utf-8")


def decode(byte_array):
    return byte_array.decode("utf-8")


def single_char_xor(byte_array, char):
    return b"".join([bytes([byte ^ char]) for byte in byte_array])


def repeating_key_xor(cipher_bytes, key_bytes):
    def ith_xor(byte, i):
        return byte ^ key_bytes[i % len(key_bytes)]

    return bytes([ith_xor(byte, i) for i, byte in enumerate(cipher_bytes)])


def bytearray_xor(byte_array_1, byte_array_2):
    iterator = zip(byte_array_1, byte_array_2)
    return b"".join(bytes([byte_1 ^ byte_2]) for byte_1, byte_2 in iterator)


def edit_distance(bytes_1, bytes_2):
    tally = [bin(byte).count("1") for byte in bytearray_xor(bytes_1, bytes_2)]
    return sum(tally)


def plaintext_scorer(byte_array_sentence):

    # ---Prescreen---
    letter_count = 0
    abnormal_char_count = 0
    for char in byte_array_sentence:
        # Count alphabet characters.
        if 64 < char < 91 or 96 < char < 123 or char == 32:
            letter_count += 1

        # Count abnormal chars (not including tab type chars).
        if not (8 < char < 16 or 31 < char < 127):
            abnormal_char_count += 1

    letter_proportion = letter_count / len(byte_array_sentence)
    abnormal_char_proportion = abnormal_char_count / len(byte_array_sentence)

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
    for byte in byte_array_sentence:
        if 96 < byte < 123: alphabet_bytes.append(byte)
        elif 64 < byte < 91: alphabet_bytes.append(byte + 22)

    # Count alphabet character frequencies.
    char_instances = list(Counter(alphabet_bytes).items())

    for char, frequency in char_instances:
        observed_frequencies[char - 97] = frequency

    # Normalise observed_frequencies.
    observed_frequencies = observed_frequencies / np.sum(observed_frequencies)

    # Return goodness of fit.
    return chisquare(observed_frequencies, f_exp=expected_frequencies)[1]


def single_char_xor_breaker(byte_array):
    def attempt_crack():
        for char in range(256):
            score = plaintext_scorer(single_char_xor(byte_array, char))
            yield score, char

    return max(attempt_crack())


def find_key_length(max_length, samples, data):

    normalised_edit_distance = np.zeros([samples])
    results = []

    for keysize in range(1, max_length):
        for pair in range(samples):

            # Take adjacent keysize length blocks.
            cipher = data[(2 * pair) * keysize:(2 * pair + 1) * keysize]
            key = data[(2 * pair + 1) * keysize:(2 * pair + 2) * keysize]

            # Calculate normalised edit distance.
            normalised_edit_distance[pair] = edit_distance(cipher,
                                                           key) / keysize

        # Store average edit distance for keysize.
        results.append([np.average(normalised_edit_distance), keysize])
    return [row[1] for row in sorted(results)]


def key_finder(key_length, data):

    # Create list of rectangular length using key_length.
    lower_multiple = len(data) - (len(data) % key_length)
    data_array = np.frombuffer(data, dtype="uint8")[0:lower_multiple]

    # Reshape to key_length length rows and transpose.
    data_array = data_array.reshape(-1, key_length)
    output_list = [bytes(row.tolist()) for row in data_array.T]

    # Return most promising key of key_length length.
    return bytes([single_char_xor_breaker(item)[1] for item in output_list])


def pad(chunk_length, data, multiples_allowed):
    #PKCS#7 padding
    if multiples_allowed == True:
        if (len(data) % chunk_length) != 0:
            pad_length = chunk_length - len(data) % chunk_length
            data += bytes([pad_length]) * pad_length
        else:
            data += bytes([chunk_length]) * chunk_length
    else:
        difference = chunk_length - len(data)
        data += bytes([difference]) * difference
    return data


def depad(data):
    #PKCS#7 depadding
    pad_length = data[-1]
    if data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise Exception("Bad padding encountered")
    return data[0:-pad_length]


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
            step_1 = bytearray_xor(iv, block)
            iv = ECB("encrypt", key, step_1)
            output_message += iv
    else:
        for block in input_message:
            step_1 = ECB("decrypt", key, block)
            output_message += bytearray_xor(iv, step_1)
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


def buffer_creator(position, append, keylength):
    #create buffers of length 15
    return (b"0" * (keylength - position - 1) + append)


def encryption_oracle(data):
    data = secrets.token_bytes(
        secrets.randbelow(5)) + data + secrets.token_bytes(
            secrets.randbelow(5))
    data_p = pad(16, data, multiples_allowed=True)
    if secrets.choice([True, False]):
        mode = "ECB"
        result = ECB("encrypt", random_AES_key(), data_p)
    else:
        mode = "CBC"
        result = CBC("encrypt", secrets.token_bytes(16), random_AES_key(),
                     data_p)
    return result, mode


def ECB_oracle(data):
    ECB_oracle.key = getattr(ECB_oracle, 'key', secrets.token_bytes(16))
    data += b64.b64decode(import_data("data_S2C12.txt"))
    data = pad(16, data, multiples_allowed=True)
    return ECB("encrypt", ECB_oracle.key, data)


def ECB_mode_check(data):
    array = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(array) - len(np.unique(array, axis=0))
    return True if 0 < duplicate_blocks else False


class set_1():
    def challenge_1(self):
        print("\n-- Challenge 1 - Convert hex to base 64 --")

        hex_ciphertext = (
            "49276d206b696c6c696e6720796f757220627261696e206c696b65"
            "206120706f69736f6e6f7573206d757368726f6f6d")
        data = bytes.fromhex(hex_ciphertext)
        B64_encode = b64.b64encode(data)

        print(f"Hex ciphertext      : {hex_ciphertext}")
        print(f"Step 1              : Hex decode")
        print(f"Decrypted plaintext : {decode(data)}")
        print(f"Base 64 encode      : {decode(B64_encode)}")

    def challenge_2(self):
        # Take two equal-length buffers and produce their XOR combination.
        print("\n-- Challenge 2 - Fixed XOR --")

        hex_ciphertext = "1c0111001f010100061a024b53535009181c"
        hex_key = "686974207468652062756c6c277320657965"

        data = bytes.fromhex(hex_ciphertext)
        key = bytes.fromhex(hex_key)

        decrypted_data = bytearray_xor(data, key)

        print(f"Hex ciphertext      : {hex_ciphertext}")
        print(f"Hex key             : {hex_key}")
        print(f"Step 1              : Hex decode")
        print(f"Step 2              : XOR decrypt")
        print(f"Decrypted plaintext : {decode(decrypted_data)}")
        print(f"Hex encode          : {decrypted_data.hex()}")

    def challenge_3(self):
        print("\n-- Challenge 3 - Single-byte XOR cipher --")

        hex_ciphertext = (
            "1b37373331363f78151b7f2b783431333d78397828372d363c7837"
            "3e783a393b3736")
        data = bytes.fromhex(hex_ciphertext)
        score, char = single_char_xor_breaker(data)

        print(f"Hex ciphertext      : {hex_ciphertext}")
        print(f"Step 1              : Hex decode")
        print(f"Step 2              : XOR data against every char and score "
              "outcomes based on char frequency analysis")
        print(f"Highest score found : {score}")
        print(f"Corresponding Key   : {char} - {chr(char)}")
        print(f"Decrypted plaintext : {decode(single_char_xor(data, char))}")

    def challenge_4(self):
        print("\n-- Challenge 4 - Detect single-char XOR --")

        file_name = "data_S1C4.txt"
        hex_ciphertext = import_data(file_name)

        def text_breaker():
            for line_index, line in enumerate(hex_ciphertext.splitlines()):
                data = bytes.fromhex(line)
                score, char = single_char_xor_breaker(data)
                yield score, char, line_index, data

        score, char, line_index, data = max(text_breaker())

        print(f"Hex data file       : {file_name}")
        print(f"Step 1              : Hex decode")
        print(f"Step 2              : XOR line of data against every char and"
              " score outcomes based on char frequency analysis")
        print(f"Step 3              : Repeat for every line")
        print(f"Highest score found : {score}")
        print(f"Corresponding line  : {line_index}")
        print(f"Corresponding key   : {char} - {chr(char)}")
        print(f"Decrypted plaintext : {decode(single_char_xor(data, char))}")

    def challenge_5(self):
        print("\n-- Challenge 5 - Implement repeating-key XOR --")

        stanza = ("Burning 'em, if you ain't quick and nimble\n"
                  "I go crazy when I hear a cymbal")
        key = encode("ICE")
        data = encode(stanza)

        print(f"Key                    : {key}")
        print(f"Plaintext              : \n{stanza}")
        print(f"Step 1                 : UTF-8 encode key and plaintext")
        print(f"Step 2                 : Encrypt with repeating key XOR")
        print(f"Hex encoded ciphertext: {repeating_key_xor(data, key).hex()}")

    def challenge_6(self):
        print(f"\n-- Challenge 6 - Break repeating-key XOR --")
        print(f"-- Part 1 --")

        string_1_data = encode("this is a test")
        string_2_data = encode("wokka wokka!!!")
        edit_dist = edit_distance(string_1_data, string_2_data)

        print(f"String 1      : {decode(string_1_data)}")
        print(f"String 2      : {decode(string_2_data)}")
        print(f"Step 1        : UTF-8 encode strings")
        print(f"Step 2        : XOR bytes and count set bits")
        print(f"Edit Distance : {edit_dist}")
        print(f"-- Part 2 --")

        B64_ciphertext = import_data("data_S1C6.txt")
        data = b64.b64decode(B64_ciphertext)
        likely_key_lengths = find_key_length(40, 10, data)

        # Find most likely key.
        def key_comparison():
            for key_length in likely_key_lengths[0:3]:
                key = key_finder(key_length, data)
                secret = repeating_key_xor(data, key)
                score = plaintext_scorer(secret)
                yield score, key, secret

        score, key, secret = max(key_comparison())

        print(f"Most likely key lengths : {likely_key_lengths[0:3]}")
        print(f"Highest score found     : {score}")
        print(f"Key                     : {decode(key)}")
        print(f"Secret                  : \n{decode(secret[:200])}...")

    def challenge_7(self):
        print(f"\n-- Challenge 7 - AES in ECB mode --")

        key = encode("YELLOW SUBMARINE")
        data = b64.b64decode(import_data("data_S1C7.txt"))
        plaintext = ECB("decrypt", key, data)

        print(f"Key    : {decode(key)}")
        print(f"Secret : \n{decode(plaintext[:200])}...")

    def challenge_8(self):
        print(f"\n-- Challenge 8 - Detect AES in ECB mode --")
        print(f"-- Method 1 --")

        hex_ciphertext = import_data("data_S1C8.txt")

        def text_breaker():
            for line_index, line in enumerate(hex_ciphertext.splitlines()):
                data = bytes.fromhex(line)
                discrete_char_instances = len(list(Counter(data).items()))
                yield discrete_char_instances, line_index

        discrete_char_instances, line_index = min(text_breaker())
        print(
            f"Assume ECB 1:1 mapping has low diversity of characters compared"
            " to random data")
        print(f"Lowest number of discrete chars : {discrete_char_instances}")
        print(f"Corresponding line              : {line_index}")
        print(f"-- Method 2 --")

        #find proportion of unique lines
        for line_index2, line in enumerate(hex_ciphertext.splitlines()):
            if ECB_mode_check(bytes.fromhex(line)): break

        print(f"Find line with least duplicate chunks")
        print(f"Corresponding line              : {line_index2}")


class set_2():
    def challenge_9(self):
        print(f"\n-- Challenge 9 - Implement PKCS#7 padding --")

        data = encode("YELLOW SUBMARINE")
        length = 20
        print(f"{data} padded to {length} bytes using PKCS#7 : "
              f"{pad(length, data, multiples_allowed=False)}")

    def challenge_10(self):
        print(f"\n-- Challenge 10 - Implement CBC mode --")

        data_p = pad(16,
                     b"This is a secret message! TOP SECRET",
                     multiples_allowed=True)
        key = pad(16, b"PASSWORD", multiples_allowed=False)
        iv = pad(16, b"12345", multiples_allowed=False)

        ECB_cyphertext = ECB("encrypt", key, data_p)
        ECB_plaintext = depad(ECB("decrypt", key, ECB_cyphertext))
        CBC_cyphertext = CBC("encrypt", iv, key, data_p)
        CBC_plaintext = depad(CBC("decrypt", iv, key, CBC_cyphertext))

        print(f"Padded Secret Message : {data_p}")
        print(f"Key                   : {key}")
        print(f"ECB encrypted message : {ECB_cyphertext}")
        print(f"ECB decrypted message : {ECB_plaintext}")
        print(f"iv                    : {iv}")
        print(f"CBC encrypted message : {b64.b64encode(CBC_cyphertext)}")
        print(f"CBC decrypted message : {CBC_plaintext}")
        print("----- Part 2 ------")

        #-- part 2 --
        data = b64.b64decode(import_data("data_S2C10.txt"))
        key = b"YELLOW SUBMARINE"
        iv = bytes([0]) * 16

        decrypted = decode(depad(CBC("decrypt", iv, key, data)))
        print(f"{decrypted[0:90]}... {decrypted[-90:-1]}")

    def challenge_11(self):
        print(f"\n-- Challenge 11 - An ECB/CBC detection oracle --")

        encryption, mode = encryption_oracle(b"A" * 100)

        print(f"Random AES Key generator   : {random_AES_key()}")
        print(f"Oracle encryption mode used: {mode}")
        print(f"ECB encrypted data?        : {ECB_mode_check(encryption)}")

    def challenge_12(self):
        print(f"\n-- Challenge 12 - "
              "Byte-at-a-time ECB decryption (Simple) --")

        def ecb_keylength_finder():
            for i in range(66):
                if (ECB_mode_check(ECB_oracle(b"0" * i))):
                    break
            return int(i / 2)

        keylength = ecb_keylength_finder()
        print(f"Calculated keylength for ECB mode : {keylength}")

        decryption = b""
        block_len = len(ECB_oracle(b""))
        for block_p in range(0, block_len, keylength):
            start = block_p
            end = block_p + keylength

            for position in range(keylength):

                buffer = buffer_creator(position, decryption, keylength)
                model = ECB_oracle(b"0" *
                                   (keylength - position - 1))[start:end]
                for char in range(256):
                    if model == ECB_oracle(buffer + bytes([char]))[start:end]:
                        decryption += bytes([char])
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
        print(f"Encrypted length  : {base_encryption_len}")
        print(f"Decrypted data    : {base_decryption}")

        #create an email that creates a whole new block in output
        end_align_email = base_email
        end_align_encryption = base_encryption
        while len(end_align_encryption) == base_encryption_len:
            end_align_email = "a" + end_align_email
            end_align_encryption = profile_for(end_align_email)
        end_align_encryption_len = len(end_align_encryption)

        print(f"End aligning email : {end_align_email}")
        print(f"Encrypted profile  : {end_align_encryption}")
        print(f"Encrypted length   : {end_align_encryption_len}")

        # add bytes to push unwanted data from encryption into end block and crop useful blocks
        bytes_to_remove = len(b"user")
        crop_email = ("b" * bytes_to_remove) + end_align_email
        crop = profile_for(crop_email)[0:48]
        decryption = profile_decrypt(crop)

        print(f"bytes to push into new block : {bytes_to_remove}")
        print(f"Crop aligning email          : {crop_email}")
        print(f"Encrypted profile crop       : {crop}")
        print(f"Crop length                  : {len(crop)}")
        print(f"Decrypted crop               : {decryption}")

        # create an email that shows its position in the encryption
        position_email = base_email
        #look for two identical blocks in encryption
        while not ECB_mode_check(profile_for(position_email)):
            position_email = "c" + position_email

        print(f"Position finding email : {position_email}")

        #find position at which duplicated block starts changing
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

        # craft new ending for encrypted data
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
        #find bytes needed to align end of blocks

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
