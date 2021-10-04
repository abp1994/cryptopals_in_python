import sys
import time
from base64 import b64decode, b64encode
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.append(str(Path(__file__).parent.resolve()))
import byte_operations as bo
import oracles as ocl
import utils as ut
from utils import decode, encode


class Set1:
    @staticmethod
    def challenge_1():
        print("\n-- Challenge 1 - Convert hex to base 64 --")

        hex_ciphertext = (
            "49276d206b696c6c696e6720796f757220627261696e206c696b65"
            "206120706f69736f6e6f7573206d757368726f6f6d")
        data = bytes.fromhex(hex_ciphertext)
        B64_encode = b64encode(data)

        print(f"Hex ciphertext : {hex_ciphertext}")
        print(f"Plaintext      : {decode(data)}")
        print(f"Base 64 encode : {decode(B64_encode)}")

    @staticmethod
    def challenge_2():
        # Take two equal-size buffers and produce their XOR combination.
        print("\n-- Challenge 2 - Fixed XOR --")

        hex_ciphertext = "1c0111001f010100061a024b53535009181c"
        hex_key = "686974207468652062756c6c277320657965"
        data = bytes.fromhex(hex_ciphertext)
        key = bytes.fromhex(hex_key)
        decrypted_data = bo.xor(data, key)

        print(f"Hex ciphertext          : {hex_ciphertext}")
        print(f"Hex key                 : {hex_key}")
        print(f"XOR decrypted plaintext : {decode(decrypted_data)}")
        print(f"Hex encode              : {decrypted_data.hex()}")

    @staticmethod
    def challenge_3():
        print("\n-- Challenge 3 - Single-byte XOR cipher --")

        hex_ciphertext = (
            "1b37373331363f78151b7f2b783431333d78397828372d363c7837"
            "3e783a393b3736")
        data = bytes.fromhex(hex_ciphertext)
        score, byte = bo.single_byte_xor_breaker(data)
        plaintext = bo.single_byte_xor(byte, data)

        print(f"Hex ciphertext                   : {hex_ciphertext}")
        print(f"Highest frequency analysis score : {score}")
        print(f"Corresponding Key                : {decode(byte)}")
        print(f"Decrypted plaintext              : {decode(plaintext)}")

    @staticmethod
    def challenge_4():
        print("\n-- Challenge 4 - Detect single-char XOR --")

        file_name = "data_S1C4.txt"
        hex_ciphertext = ut.import_data(file_name)

        def text_breaker():
            for line_index, line in enumerate(hex_ciphertext.splitlines()):
                data = bytes.fromhex(line)
                score, byte = bo.single_byte_xor_breaker(data)
                yield score, byte, line_index, data

        score, byte, line_index, data = max(text_breaker())
        plaintext = bo.single_byte_xor(byte, data)

        print(f"Hex data file                    : {file_name}")
        print(f"Highest frequency analysis score : {score}")
        print(f"Corresponding line               : {line_index}")
        print(f"Corresponding key                : {decode(byte)}")
        print(f"Decrypted plaintext              : {decode(plaintext)}")

    @staticmethod
    def challenge_5():
        print("\n-- Challenge 5 - Implement repeating-key XOR --")

        stanza = ("Burning 'em, if you ain't quick and nimble\n"
                  "I go crazy when I hear a cymbal")
        key = encode("ICE")
        data = encode(stanza)
        ciphertext = bo.repeating_key_xor(data, key)

        print(f"Key                                : {key}")
        print(f"Plaintext                          : \n{stanza}")
        print(f"Repeating key encrypt (hex encode) : {ciphertext.hex()}")

    @staticmethod
    def challenge_6():
        print(f"\n-- Challenge 6 - Break repeating-key XOR --")
        print(f"-- Part 1 --")

        data_1 = encode("this is a test")
        data_2 = encode("wokka wokka!!!")

        print(f"String 1      : {decode(data_1)}")
        print(f"String 2      : {decode(data_2)}")
        print(f"Edit distance : {bo.edit_distance(data_1, data_2)}")
        print(f"-- Part 2 --")

        B64_ciphertext = ut.import_data("data_S1C6.txt")
        data = b64decode(B64_ciphertext)
        likely_key_sizes = bo.find_key_size(40, data)

        # Find most likely key.
        def key_comparison():
            for key_size in likely_key_sizes[0:3]:
                key = bo.key_finder(key_size, data)
                secret = bo.repeating_key_xor(data, key)
                score = bo.text_scorer(secret).score()
                yield score, key, secret

        score, key, secret = max(key_comparison())

        print(f"Most likely key sizes : {likely_key_sizes[0:3]}")
        print(f"Highest score         : {score}")
        print(f"Corresponding Key     : {decode(key)}")
        print(f"Secret                : \n{decode(secret[:90])}...")

    @staticmethod
    def challenge_7():
        print(f"\n-- Challenge 7 - AES in ECB mode --")

        key = encode("YELLOW SUBMARINE")
        data = b64decode(ut.import_data("data_S1C7.txt"))
        plaintext = ocl.AESECB(key).decrypt(data)

        print(f"Key    : {decode(key)}")
        print(f"Secret : \n{decode(plaintext[:90])}...")

    @staticmethod
    def challenge_8():
        print(f"\n-- Challenge 8 - Detect AES in ECB mode --")
        print(f"-- Method 1 --")

        hex_ciphertext = ut.import_data("data_S1C8.txt")

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

        # Find if data contains duplicate blocks.
        for line_index2, line in enumerate(hex_ciphertext.splitlines()):
            if bo.ECB_mode_check(bytes.fromhex(line)):
                break

        print(f"Find line with duplicate blocks")
        print(f"Corresponding line            : {line_index2}")


class Set2:
    @staticmethod
    def challenge_9():
        print(f"\n-- Challenge 9 - Implement PKCS#7 padding --")

        data = encode("YELLOW SUBMARINE")
        size = 20
        print(f"{data} padded to {size} bytes using PKCS#7 : "
              f"{bo.pad(size, data)}")

    @staticmethod
    def challenge_10():
        print(f"\n-- Challenge 10 - Implement CBC mode --")

        data_p = bo.pad(16, b"This is a secret message! TOP SECRET")
        key = b"PASSWORDPASSWORD"
        iv = b"1122334455667788"

        ECB_1 = ocl.AESECB(key)
        CBC_1 = ocl.AESCBC(iv, key)

        ECB_ciphertext = ECB_1.encrypt(data_p)
        ECB_plaintext = bo.depad(ECB_1.decrypt(ECB_ciphertext))
        CBC_ciphertext = CBC_1.encrypt(data_p)
        CBC_plaintext = bo.depad(CBC_1.decrypt(CBC_ciphertext))

        print(f"Padded Secret Message : {data_p}")
        print(f"Key                   : {key}")
        print(f"ECB encrypted message : {ECB_ciphertext}")
        print(f"ECB decrypted message : {ECB_plaintext}")
        print(f"iv                    : {iv}")
        print(f"CBC encrypted message : {CBC_ciphertext}")
        print(f"CBC decrypted message : {CBC_plaintext}")
        print("----- Part 2 ------")

        data = b64decode(ut.import_data("data_S2C10.txt"))
        key = b"YELLOW SUBMARINE"
        iv = bytes([0]) * 16
        CBC_2 = ocl.AESCBC(iv, key)
        decrypted = decode(bo.depad(CBC_2.decrypt(data)))
        print(f"CBC decrypted message : \n{decrypted[0:90]}...")

    @staticmethod
    def challenge_11():
        print(f"\n-- Challenge 11 - An ECB/CBC detection oracle --")

        # Create and profile 5 oracles.
        oracles = [ocl.C11() for i in range(5)]
        detected_modes = [ocl.Profiler(oracle).mode for oracle in oracles]

        print(f"Random AES key : {bo.random_AES_key()}")
        print(f"Oracle modes   : {[oracle.mode for oracle in oracles]}")
        print(f"Detected modes : {detected_modes}")

    @staticmethod
    def challenge_12():
        print(f"\n-- Challenge 12 - "
              "Byte-at-a-time ECB decryption (Simple) --")

        oracle = ocl.C12()
        profile = ocl.Profiler(oracle)

        print(f"Detected oracle mode    : {profile.mode}")
        print(f"Detected block size     : {profile.block_size}")
        print(f"Input entry block index : {profile.entry_block_index}")
        print(f"Input entry byte index  : {profile.entry_byte_index}")

        decryption = b""
        data_size_in_blocks = int(
            len(oracle.encrypt(b"")) / profile.block_size)

        # For all blocks in the data.
        for block_index in range(data_size_in_blocks):
            block_start_byte_index = block_index * profile.block_size
            block_end_byte_index = block_start_byte_index + profile.block_size

            # For all byte positions along the block (15->0).
            for byte_index in reversed(range(profile.block_size)):
                buffer = b"0" * byte_index + decryption
                model_bytes = oracle.encrypt(
                    b"0" *
                    (byte_index))[block_start_byte_index:block_end_byte_index]

                # Test all possible characters against model_byte.
                for char in range(256):
                    byte = bytes([char])
                    # If character matched add it to the decryption.
                    if model_bytes == oracle.encrypt(
                            buffer +
                            byte)[block_start_byte_index:block_end_byte_index]:
                        decryption += byte
                        break

        print(f"Decoded message : \n{decode(bo.depad(decryption))}")

    @staticmethod
    def challenge_13():
        print(f"\n-- Challenge 13 - ECB cut-and-paste --")
        print(f"-- Part 1 --")

        text = """foo=bar&baz=qux&zap=zazzle"""
        email = "hello@world.com"
        parsed = ocl.profile_parse(email)

        print(f"Example string   : {text}")
        print(f"Unpacked profile : {ocl.profile_unpack(encode(text))}")
        print(f"Example Email    : {email}")
        print(f"Parsed profile   : {parsed}")
        print(f"Unpacked profile : {ocl.profile_unpack(parsed)}")
        print(f"-- Part 2 --")

        base_email = "user@hack.com"
        base_encryption = ocl.profile_create(base_email)
        base_encryption_len = len(base_encryption)
        base_decryption = ocl.profile_decrypt(base_encryption)

        print(f"Base email         : {base_email}")
        print(f"Encrypted profile  : {base_encryption}")
        print(f"Encrypted size     : {base_encryption_len}")
        print(f"Decrypted data     : {base_decryption}")

        # Create an email that creates a whole new block in output.
        end_align_email = base_email
        end_align_encryption = base_encryption
        while len(end_align_encryption) == base_encryption_len:
            end_align_email = "a" + end_align_email
            end_align_encryption = ocl.profile_create(end_align_email)
        end_align_encryption_len = len(end_align_encryption)

        print(f"End aligning email : {end_align_email}")
        print(f"Encrypted profile  : {end_align_encryption}")
        print(f"Encrypted size     : {end_align_encryption_len}")

        # Add bytes to push unwanted data from encryption into end
        # block and crop useful blocks.
        bytes_to_remove = len(b"user")
        crop_email = ("b" * bytes_to_remove) + end_align_email
        crop = ocl.profile_create(crop_email)[0:48]
        decryption = ocl.profile_decrypt(crop)

        print(f"bytes to push into new block : {bytes_to_remove}")
        print(f"Crop aligning email          : {crop_email}")
        print(f"Encrypted profile crop       : {crop}")
        print(f"Crop size                    : {len(crop)}")
        print(f"Decrypted crop               : {decryption}")

        # Create an email that shows its position in the encryption.
        position_email = base_email
        # Look for two identical blocks in encryption.
        while not bo.ECB_mode_check(ocl.profile_create(position_email)):
            position_email = "c" + position_email

        print(f"Position finding email       : {position_email}")

        # Find position at which duplicated block starts changing.
        position = 0
        while bo.ECB_mode_check(ocl.profile_create(position_email)):
            position_email_list = list(position_email)
            position_email_list[position] = "d"
            position_email = "".join(position_email_list)
            position += 1
        position -= 1

        print(f"Position finding email       : {position_email}")
        print(f"Position of block start      : {position}")

        bytes_to_add = position - len(base_email)
        if bytes_to_add < 0: bytes_to_add += 16
        block_end_email = ("e" * bytes_to_add) + base_email

        print(f"Bytes to add to email        : {bytes_to_add}")
        print(f"Email ending block           : {block_end_email}")

        # Craft new ending for encrypted data.
        new_end = decode(bo.pad(16, b"admin"))
        new_end_encryption_email = block_end_email + new_end
        cut = ocl.profile_create(new_end_encryption_email)[32:48]
        decrypted_cut = ocl.profile_decrypt(cut)

        print(f"new end encrypting email     : {new_end_encryption_email}")
        print(f"new ending encryption        : {cut}")
        print(f"new ending decrypted         : {decrypted_cut}")

        attacker_encrypted_profile = crop + cut
        attacker_decrypted_profile = ocl.profile_decrypt(
            attacker_encrypted_profile)
        attacker_profile = ocl.profile_unpack(
            bo.depad(attacker_decrypted_profile))

        print(f"Attacker encrypted profile   : {attacker_encrypted_profile}")
        print(f"Attacker decrypted profile   : {attacker_decrypted_profile}")
        print(f"Attacker  profile            : {attacker_profile}")

    @staticmethod
    def challenge_14():
        print(f"\n-- Challenge 14 - Byte-at-a-time ECB decryption (Harder) --")

        oracle = ocl.C14()
        profile = ocl.Profiler(oracle)

        print(f"Detected oracle mode    : {profile.mode}")
        print(f"Detected block size     : {profile.block_size}")
        print(f"Input entry block index : {profile.entry_block_index}")
        print(f"Input entry byte index  : {profile.entry_byte_index}")
        print(f"Size of output          : {profile.model_size}")

        print(f"To be completed...!")

        # Create an input that fills the current block.
        bytes_to_add = profile.block_size - profile.entry_byte_index
        block_end_input = b"a" * bytes_to_add

        print(f"Bytes to add        : {bytes_to_add}")
        print(f"Input ending block  : {block_end_input}")

        decryption = b""
        data_size_in_blocks = int(
            len(oracle.encrypt(b"")) / profile.block_size)

        print(f"Size of output in blocks         : {data_size_in_blocks}")

        # For all blocks in the data after the prefix blocks.
        for block_index in range(profile.entry_block_index + 1,
                                 data_size_in_blocks):
            block_start_byte_index = block_index * profile.block_size
            block_end_byte_index = block_start_byte_index + profile.block_size
            print(f"block_i: {block_index}")

            # For all byte positions along the block (15->0).
            for byte_position in reversed(range(profile.block_size)):
                buffer = block_end_input + (b"0" * byte_position) + decryption
                model_bytes = oracle.encrypt(
                    block_end_input + (b"0" * (byte_position))
                )[block_start_byte_index:block_end_byte_index]
                print(f"byte_i: {byte_position}")
                print(f"model: {model_bytes}")
                print(len(model_bytes))

                # Test all possible characters against model_byte.
                for char in range(256):
                    byte = bytes([char])
                    # If character matched add it to the decryption.
                    if model_bytes == oracle.encrypt(
                            buffer +
                            byte)[block_start_byte_index:block_end_byte_index]:
                        decryption += byte

                        break
                    if char == 255: raise Exception("No match found")
                print(f"match found :{decryption}")

        print(decryption)
        """print(
            f"Decoded message : \n{decode(bo.depad((b'0'*(profile.entry_block_index-1))+decryption))}"
        )"""

    @staticmethod
    def challenge_15():
        print(f"\n-- Challenge 15 - PKCS#7 padding validation --")

        a = b"ICE ICE BABY\x04\x04\x04\x04"
        b = b"ICE ICE BABY\x05\x05\x05\x05"
        c = b"ICE ICE BABY\x01\x02\x03\x04"

        for i in [a, b, c]:
            try:
                print(f"Depad of {i} : {bo.depad(i)}")
            except Exception as e:
                print(f"Depad of {i} : {e}")


def run_challenges():

    Set1.challenge_1()
    Set1.challenge_2()
    Set1.challenge_3()
    Set1.challenge_4()
    Set1.challenge_5()
    Set1.challenge_6()
    Set1.challenge_7()
    Set1.challenge_8()

    Set2.challenge_9()
    Set2.challenge_10()
    Set2.challenge_11()

    Set2.challenge_12()

    Set2.challenge_13()
    #Set2.challenge_14()
    Set2.challenge_15()


def main():
    print("\n\n-- The Cryptopals Crypto Challenges in Python by Akaash BP --")
    # https://cryptopals.com
    startTime = time.time()

    # profiling stat options
    # function_stats('set_1.challenge_4()')
    # print(sys.path)

    run_challenges()

    executionTime = (time.time() - startTime)
    print(f'\nExecution time in seconds: {executionTime}')

    print("Press return to exit.")
    input()


if __name__ == "__main__":
    main()
