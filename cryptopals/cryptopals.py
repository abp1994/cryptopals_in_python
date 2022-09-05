import base64
import sys
import time
from base64 import b64decode, b64encode
from logging import raiseExceptions
from pathlib import Path
from pydoc import plain
from random import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.append(str(Path(__file__).parent.resolve()))

import byte_operations as bo
import oracles as ocl
import utils as ut
from utils import decode, encode


class Set1:
    @staticmethod
    def challenge_1():
        print("\n-- Challenge 1 - Convert hex to base 64 --")

        plaintext_hex = (
            "49276d206b696c6c696e6720796f757220627261696e206c696b65"
            "206120706f69736f6e6f7573206d757368726f6f6d")
        plaintext = bytes.fromhex(plaintext_hex)
        plaintext_b64 = b64encode(plaintext)

        print(f"Hex plaintext  : {plaintext_hex}")
        print(f"Plaintext      : {decode(plaintext)}")
        print(f"Base 64 encode : {decode(plaintext_b64)}")
        return plaintext_b64

    @staticmethod
    def challenge_2():
        print("\n-- Challenge 2 - Fixed XOR --")

        ciphertext_hex = "1c0111001f010100061a024b53535009181c"
        key_hex = "686974207468652062756c6c277320657965"
        ciphertext, key = map(bytes.fromhex, [ciphertext_hex, key_hex])
        plaintext = bo.xor(ciphertext, key)

        print(f"Hex ciphertext          : {ciphertext_hex}")
        print(f"Hex key                 : {key_hex}")
        print(f"XOR decrypted plaintext : {decode(plaintext)}")
        print(f"Hex encode              : {plaintext.hex()}")
        return plaintext.hex()

    @staticmethod
    def challenge_3():
        print("\n-- Challenge 3 - Single-byte XOR cipher --")

        ciphertext_hex = (
            "1b37373331363f78151b7f2b783431333d78397828372d363c7837"
            "3e783a393b3736")
        ciphertext = bytes.fromhex(ciphertext_hex)
        score, byte = bo.crack_single_byte_xor(ciphertext)
        plaintext = bo.single_byte_xor(byte, ciphertext)

        print(f"Hex ciphertext                   : {ciphertext_hex}")
        print(f"Highest frequency analysis score : {score}")
        print(f"Corresponding Key                : {decode(byte)}")
        print(f"Decrypted plaintext              : {decode(plaintext)}")
        return decode(plaintext)

    @staticmethod
    def challenge_4():
        print("\n-- Challenge 4 - Detect single-char XOR --")

        file_name = "data_S1C4.txt"
        ciphertext_hex = ut.import_data(file_name)

        def crack_text():
            for line_index, line in enumerate(ciphertext_hex.splitlines()):
                data = bytes.fromhex(line)
                score, byte = bo.crack_single_byte_xor(data)
                yield score, byte, line_index, data

        score, byte, line_index, data = max(crack_text())
        plaintext = bo.single_byte_xor(byte, data)

        print(f"Hex data file                    : {file_name}")
        print(f"Highest frequency analysis score : {score}")
        print(f"Corresponding line               : {line_index}")
        print(f"Corresponding key                : {decode(byte)}")
        print(f"Decrypted plaintext              : {decode(plaintext)}")
        return decode(plaintext)

    @staticmethod
    def challenge_5():
        print("\n-- Challenge 5 - Implement repeating-key XOR --")

        plaintext = encode("Burning 'em, if you ain't quick and nimble\n"
                           "I go crazy when I hear a cymbal")
        key = encode("ICE")
        ciphertext = bo.repeating_key_xor(plaintext, key)

        print(f"Key                                : {decode(key)}")
        print(f"Plaintext                          : \n{decode(plaintext)}")
        print(f"Repeating key encrypt (hex encode) : {ciphertext.hex()}")
        return (ciphertext.hex())

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

        ciphertext_b64 = ut.import_data("data_S1C6.txt")
        ciphertext = b64decode(ciphertext_b64)
        likely_key_sizes = bo.find_key_size(40, ciphertext)

        # Find most likely key.
        def key_comparison():
            for key_size in likely_key_sizes[0:3]:
                key = bo.key_finder(key_size, ciphertext)
                secret = bo.repeating_key_xor(ciphertext, key)
                score = bo.text_scorer(secret).score()
                yield score, key, secret

        score, key, secret = max(key_comparison())

        print(f"Most likely key sizes : {likely_key_sizes[0:3]}")
        print(f"Highest score         : {score}")
        print(f"Corresponding Key     : {decode(key)}")
        print(f"Secret                : \n{decode(secret[:90])}...")
        return decode(secret)

    @staticmethod
    def challenge_7():
        print(f"\n-- Challenge 7 - AES in ECB mode --")

        key = encode("YELLOW SUBMARINE")
        ciphertext = b64decode(ut.import_data("data_S1C7.txt"))
        plaintext = ocl.AESECB(key).decrypt(ciphertext)

        print(f"Key       : {decode(key)}")
        print(f"Plaintext : \n{decode(plaintext[:90])}...")

    @staticmethod
    def challenge_8():
        print(f"\n-- Challenge 8 - Detect AES in ECB mode --")

        ciphertext_hex = ut.import_data("data_S1C8.txt")
        # Find if data contains duplicate blocks.
        for line_index, line in enumerate(ciphertext_hex.splitlines()):
            if bo.is_ecb_encrypted(bytes.fromhex(line)):
                break

        print(f"Line with duplicate blocks : {line_index}")
        return line_index


class Set2:
    @staticmethod
    def challenge_9():
        print(f"\n-- Challenge 9 - Implement PKCS#7 padding --")

        plaintext = encode("YELLOW SUBMARINE")
        size = 20
        plaintext_padded = bo.pad(size, plaintext)

        print(f"{plaintext} padded to {size} bytes using PKCS#7 : "
              f"{plaintext_padded}")
        return plaintext_padded

    @staticmethod
    def challenge_10():
        print(f"\n-- Challenge 10 - Implement CBC mode --")

        plaintext_padded = bo.pad(16, b"This is a secret message! TOP SECRET")
        key = b"PASSWORDPASSWORD"
        iv = b"1122334455667788"

        ECB_1 = ocl.AESECB(key)
        CBC_1 = ocl.AESCBC(iv, key)

        ciphertext_ecb = ECB_1.encrypt(plaintext_padded)
        plaintext_ecb = bo.depad(ECB_1.decrypt(ciphertext_ecb))
        ciphertext_cbc = CBC_1.encrypt(plaintext_padded)
        plaintext_cbc = bo.depad(CBC_1.decrypt(ciphertext_cbc))

        print(f"Padded Secret Message : {plaintext_padded}")
        print(f"Key                   : {key}")
        print(f"ECB encrypted message : {ciphertext_ecb}")
        print(f"ECB decrypted message : {plaintext_ecb}")
        print(f"iv                    : {iv}")
        print(f"CBC encrypted message : {ciphertext_cbc}")
        print(f"CBC decrypted message : {plaintext_cbc}")
        print("----- Part 2 ------")

        ciphertext = b64decode(ut.import_data("data_S2C10.txt"))
        key = b"YELLOW SUBMARINE"
        iv = bytes([0]) * 16
        CBC_2 = ocl.AESCBC(iv, key)
        plaintext = bo.depad(CBC_2.decrypt(ciphertext))
        print(f"CBC decrypted message : \n{decode(plaintext[0:90])}...")
        return decode(plaintext)

    @staticmethod
    def challenge_11():
        print(f"\n-- Challenge 11 - An ECB/CBC detection oracle --")

        # Create and profile 5 oracles.
        oracles = [ocl.C11() for _ in range(5)]
        oracle_modes = [oracle.mode for oracle in oracles]
        detected_modes = [ocl.Profiler(oracle).mode for oracle in oracles]

        print(f"Random AES key : {bo.random_AES_key()}")
        print(f"Oracle modes   : {oracle_modes}")
        print(f"Detected modes : {detected_modes}")
        return oracle_modes, detected_modes

    @staticmethod
    def challenge_12():
        print(f"\n-- Challenge 12 -"
              "Byte-at-a-time ECB decryption (Simple) --")

        oracle = ocl.C12()
        profile = ocl.Profiler(oracle)

        print(f"Detected oracle mode       : {profile.mode}")
        print(f"Detected bytes in output   : {profile.model_size}")
        print(f"Detected block size        : {profile.block_size}")
        print(f"Detected input block index : {profile.input_block_index}")
        print(f"Detected input byte index  : {profile.input_byte_index}")
        print(f"Detected initial pad size  : {profile.initial_pad_size}")

        decryption = b""
        data_size_in_blocks = int(
            len(oracle.encrypt(b"")) / profile.block_size)

        # For all blocks in the data.
        for block_index in range(data_size_in_blocks):
            block_start_byte_index = block_index * profile.block_size
            block_end_byte_index = block_start_byte_index + profile.block_size

            # For all byte positions along the block (15->0).
            for byte_index in reversed(range(profile.block_size)):
                buffer = b"Z" * byte_index + decryption
                model_block = oracle.encrypt(
                    b"Z" *
                    (byte_index))[block_start_byte_index:block_end_byte_index]

                # Test all possible characters against model_block.
                for char in range(256):
                    byte = bytes([char])
                    # If character matched add it to the decryption.
                    if model_block == oracle.encrypt(
                            buffer +
                            byte)[block_start_byte_index:block_end_byte_index]:
                        decryption = b"".join([decryption, byte])
                        break
        plaintext = bo.depad(decryption)
        print(f"Decoded message : \n{decode(plaintext)}")
        return decode(plaintext)

    @staticmethod
    def challenge_13():
        print(f"\n-- Challenge 13 - ECB cut-and-paste --")
        print(f"-- Part 1 --")

        text = """foo=bar&baz=qux&zap=zazzle"""
        email = "hello@world.com"
        oracle = ocl.C13
        parsed = oracle.parse_profile(email)

        print(f"Example string   : {text}")
        print(f"Unpacked profile : {oracle.unpack_profile(encode(text))}")
        print(f"Example Email    : {email}")
        print(f"Parsed profile   : {parsed}")
        print(f"Unpacked profile : {oracle.unpack_profile(parsed)}")
        print(f"-- Part 2 --")

        base_email = "user@hack.com"
        base_encryption = oracle.create_profile(base_email)
        base_encryption_len = len(base_encryption)
        base_decryption = oracle.decrypt_profile(base_encryption)

        print(f"Base email         : {base_email}")
        print(f"Encrypted profile  : {base_encryption}")
        print(f"Encrypted size     : {base_encryption_len}")
        print(f"Decrypted data     : {base_decryption}")

        # Create an email that creates a whole new block in output.
        end_align_email = base_email
        end_align_encryption = base_encryption

        while len(end_align_encryption) == base_encryption_len:
            end_align_email = "a" + end_align_email
            end_align_encryption = oracle.create_profile(end_align_email)
        end_align_encryption_len = len(end_align_encryption)

        print(f"End aligning email : {end_align_email}")
        print(f"Encrypted profile  : {end_align_encryption}")
        print(f"Encrypted size     : {end_align_encryption_len}")

        # Add bytes to push unwanted data from encryption into end
        # block and crop useful blocks.
        bytes_to_remove = len(b"user")
        crop_email = ("b" * bytes_to_remove) + end_align_email
        crop = oracle.create_profile(crop_email)[0:48]
        decryption = oracle.decrypt_profile(crop)

        print(f"Bytes to push into new block : {bytes_to_remove}")
        print(f"Crop aligning email          : {crop_email}")
        print(f"Encrypted profile crop       : {crop}")
        print(f"Crop size                    : {len(crop)}")
        print(f"Decrypted crop               : {decryption}")

        # Create an email that shows its position in the encryption.
        position_email = base_email
        # Look for two identical blocks in encryption.
        while not bo.is_ecb_encrypted(oracle.create_profile(position_email)):
            position_email = "c" + position_email

        print(f"Position finding email       : {position_email}")

        # Find position at which duplicated block starts changing.
        position = 0
        while bo.is_ecb_encrypted(oracle.create_profile(position_email)):
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
        cut = oracle.create_profile(new_end_encryption_email)[32:48]
        decrypted_cut = oracle.decrypt_profile(cut)

        print(f"new end encrypting email     : {new_end_encryption_email}")
        print(f"new ending encryption        : {cut}")
        print(f"new ending decrypted         : {decrypted_cut}")

        attacker_encrypted_profile = crop + cut
        attacker_decrypted_profile = oracle.decrypt_profile(
            attacker_encrypted_profile)
        attacker_profile = oracle.unpack_profile(
            bo.depad(attacker_decrypted_profile))

        print(f"Attacker encrypted profile   : {attacker_encrypted_profile}")
        print(f"Attacker decrypted profile   : {attacker_decrypted_profile}")
        print(f"Attacker  profile            : {attacker_profile}")
        return attacker_profile

    @staticmethod
    def challenge_14():
        print(f"\n-- Challenge 14 - Byte-at-a-time ECB decryption (Harder) --")

        oracle = ocl.C14()
        profile = ocl.Profiler(oracle)

        print(f"Detected oracle mode       : {profile.mode}")
        print(f"Detected bytes in output   : {profile.model_size}")
        print(f"Detected block size        : {profile.block_size}")
        print(f"Detected input block index : {profile.input_block_index}")
        print(f"Detected initial pad size  : {profile.initial_pad_size}")
        print(f"Detected input byte index  : {profile.input_byte_index}")

        # Create an input that fills the current block, by using 1 to block_size bytes.
        bytes_to_add = profile.block_size - (profile.input_byte_index %
                                             profile.block_size)
        block_end_input = b"Z" * bytes_to_add

        print(f"Bytes to add               : {bytes_to_add}")
        print(f"Input ending block         : {block_end_input}")

        decryption = b""
        data_size_in_blocks = int(
            len(oracle.encrypt(b"")) / profile.block_size)

        print(f"Size of output             : {profile.model_size}")
        print(f"Size of output in blocks   : {data_size_in_blocks}")

        # For all blocks in the data after the prefix blocks.
        for block_index in range(profile.input_block_index + 1,
                                 data_size_in_blocks + 1):
            block_start_byte_index = block_index * profile.block_size
            block_end_byte_index = block_start_byte_index + profile.block_size

            # For all byte positions along the block (15->0).
            for byte_position in reversed(range(profile.block_size)):
                buffer = block_end_input + (b"Z" * byte_position) + decryption
                model_block = oracle.encrypt(
                    block_end_input + (b"Z" * (byte_position))
                )[block_start_byte_index:block_end_byte_index]

                # Test all possible characters against model_block.
                for char in range(256):
                    byte = bytes([char])
                    # If character matched add it to the decryption.
                    if model_block == oracle.encrypt(
                            buffer +
                            byte)[block_start_byte_index:block_end_byte_index]:
                        decryption = b"".join([decryption, byte])
                        break

        plaintext = bo.depad(decryption)
        print(f"Decoded message : \n{decode(plaintext)}")
        return decode(plaintext)

    @staticmethod
    def challenge_15():
        print(f"\n-- Challenge 15 - PKCS#7 padding validation --")

        a = b"ICE ICE BABY\x04\x04\x04\x04"
        b = b"ICE ICE BABY\x05\x05\x05\x05"
        c = b"ICE ICE BABY\x01\x02\x03\x04"

        for padded_text in [a, b, c]:
            try:
                print(f"Depad of {padded_text} : {bo.depad(padded_text)}")
            except Exception as e:
                print(f"Depad of {padded_text} : {e}")

    @staticmethod
    def challenge_16():
        print(f"\n-- Challenge 16 - CBC bitflipping attacks --")

        oracle = ocl.C16()
        profile = ocl.Profiler(oracle)

        print(f"Detected oracle mode       : {profile.mode}")
        print(f"Detected bytes in output   : {profile.model_size}")
        print(f"Detected block size        : {profile.block_size}")
        print(f"Detected input block index : {profile.input_block_index}")
        print(f"Detected initial pad size  : {profile.initial_pad_size}")
        print(f"Detected input byte index  : {profile.input_byte_index}")

        # Known properties of oracle.
        known_prefix = b"comment1=cooking%20MCs;userdata="

        # Create an input that is similar to the desired injection.
        crack_input = b",admin-true"
        ciphertext = oracle.encrypt(crack_input)

        # Bit flip desired characters at desired index.
        bit_flipped_ciphertext_1 = bo.CBC_bit_flipper(known_prefix,
                                                      crack_input, ciphertext,
                                                      profile.block_size, 0,
                                                      ";")

        bit_flipped_ciphertext_2 = bo.CBC_bit_flipper(
            known_prefix, crack_input, bit_flipped_ciphertext_1,
            profile.block_size, 6, "=")

        # Check decryption.
        print(f"Decrypted data : \n{oracle.decrypt(bit_flipped_ciphertext_2)}")
        print(
            f"Admin property present : {oracle.is_admin(bit_flipped_ciphertext_2)}"
        )
        return oracle.is_admin(bit_flipped_ciphertext_2)


class Set3:
    @staticmethod
    def challenge_17():
        print(f"\n-- Challenge 17 - The CBC padding oracle --")

        oracle = ocl.C17()
        ciphertext, iv = oracle.encrypt()

        # Find output size.
        block_size = 16
        output_size = len(ciphertext)
        model_size = int(len(ciphertext) / block_size)

        print(f"Ciphertext           : {ciphertext}")
        print(f"Assumed Block Size   : {block_size}")
        print(f"Output size in bytes : {output_size}")
        print(f"Number of Blocks     : {model_size}")
        print(f"Revealed data        : {oracle.reveal()}")
        print(f"Revealed data depad  : {bo.depad(oracle.reveal())}")
        print(f"Revealed data length : {len(bo.depad(oracle.reveal()))}")

        # Find the index of the last byte of the last but 1 block (Byte that affects padding byte after encryption).
        '''injection_byte_index = output_size - block_size - 1
        print(f"Injection byte index : {injection_byte_index}")'''

        #decryption = b""
        #expected_pad = 1

        # Function that submits all possible values for specific byte index in a ciphertext and returns byte that oracle is able to depad.
        # a bit is then flipped and depading is rerun to check that the padding is of a known value.
        def single_byte_pad_crack(ciphertext, iv, index, expected_pad):
            crack_ciphertext = bytearray(ciphertext)

            for byte in range(255):
                crack_ciphertext[index] = byte

                if (oracle.depad_possible(crack_ciphertext, iv)):

                    # Check padding is of correct size by flipping a bit that should not affect the pad.
                    # Only required if expected pad is 1.
                    if expected_pad == 1:
                        check_crack_ciphertext = crack_ciphertext[:]
                        # Flip single bit by XORing with 1.
                        check_crack_ciphertext[
                            index - expected_pad] = check_crack_ciphertext[
                                index - expected_pad] ^ 1
                        # Check depad still possible.
                        if (oracle.depad_possible(check_crack_ciphertext, iv)):
                            break
                    else:
                        break
            return byte

        def padding_oracle_attack(ciphertext, block_size, iv):
            plaintext = b""

            # Divide ciphertext into blocks.
            block_array = bo.blockify(ciphertext, block_size)

            # Prepend the iv to blocks.
            block_array.insert(0, iv)

            # Create block pairs for processing.
            block_pairs = [(block_array[i], block_array[i + 1])
                           for i in (range(len(block_array) - 1))]

            for penultimate_block, end_block in reversed(block_pairs):
                decryption = b""
                crack_block = penultimate_block[:]
                # Crack each byte in the block.
                for byte_index in reversed(range(block_size)):
                    expected_pad = block_size - byte_index

                    crack_ciphertext = b"".join([crack_block, end_block])

                    # Find the valid pad byte.
                    valid_pad_byte = single_byte_pad_crack(
                        crack_ciphertext, iv, byte_index, expected_pad)

                    # Find the plaintext byte using the valid pad byte.
                    decrypted_byte = expected_pad ^ penultimate_block[
                        byte_index] ^ valid_pad_byte

                    # Prepend decrypted byte to decryption.
                    decryption = b"".join(
                        [bytes([decrypted_byte]), decryption])

                    # Update crack block by setting all unknown pad bytes to bytes that create expected pad when decrypted.
                    for index in range(block_size - 1,
                                       block_size - expected_pad - 1, -1):
                        crack_block_prefix = crack_block[:index]
                        crack_block_suffix = crack_block[index + 1:]
                        new_crack_byte = penultimate_block[index] ^ decryption[
                            -(block_size - index)] ^ expected_pad + 1

                        crack_block = b"".join([
                            crack_block_prefix,
                            bytes([new_crack_byte]), crack_block_suffix
                        ])

                # Update plaintext by prepending decrypted block.
                plaintext = b"".join([decryption, plaintext])
                print(plaintext)
            # Remove padding from plaintext.
            print(plaintext)
            plaintext = bo.depad(plaintext)
            return plaintext

        plaintext = padding_oracle_attack(ciphertext, block_size, iv)
        print(f'Plaintext     : {plaintext}')
        if plaintext == bo.depad(oracle.reveal()):
            print("---------------Success------------------")
        else:
            print("XXXXXXXXXXXXXXXXFailureXXXXXXXXXXXXXXXX")
            raise Exception("C17 Failed")

    def challenge_18():
        print(f"\n-- Challenge 18 - Implement CTR, the stream cipher mode --")
        ciphertext = b64decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
        )

        key = encode("YELLOW SUBMARINE")
        nonce = b'\x00' * 8

        cipher = ocl.AESCTR(nonce, key)
        plaintext = cipher.decrypt(ciphertext)

        print(f"Key                :  {decode(key)}")
        print(f"Nonce              :  {nonce}")
        print(f"Decrypted plaintext : {decode(plaintext)}")

        secret = encode("Top Secret info Here -blah blah blah-")
        key = encode("PASSWORDPASSWORD")
        nonce = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        cipher2 = ocl.AESCTR(nonce, key)

        cipher_chunk_1 = cipher2.encrypt(secret[:7])
        cipher_chunk_2 = cipher2.encrypt(secret[7:])

        chunk_1 = cipher2.decrypt(cipher_chunk_1)
        chunk_2 = cipher2.decrypt(cipher_chunk_2)

        plaintext_2 = b"".join([chunk_1, chunk_2])

        print(f"Secret             :  {decode(secret)}")
        print(f"Key                :  {decode(key)}")
        print(f"Nonce              :  {nonce}")
        print(f"Chunk 1 encryption :  {cipher_chunk_1}")
        print(f"Chunk 2 encryption :  {cipher_chunk_2}")
        print(f"Chunk 1 decryption :  {chunk_1}")
        print(f"Chunk 2 decryption :  {chunk_2}")
        print(f"Plaintext          :  {decode(plaintext_2)}")
        return plaintext, secret, plaintext_2

    def challenge_19():
        print(f"\n-- Break fixed-nonce CTR mode using substitutions --")
        return


def run_challenges():

    # Set 1.
    Set1.challenge_1()
    Set1.challenge_2()
    Set1.challenge_3()
    Set1.challenge_4()
    Set1.challenge_5()
    Set1.challenge_6()
    Set1.challenge_7()
    Set1.challenge_8()

    # Set 2.
    Set2.challenge_9()
    Set2.challenge_10()
    Set2.challenge_11()
    Set2.challenge_12()
    Set2.challenge_13()
    Set2.challenge_14()
    Set2.challenge_15()
    Set2.challenge_16()

    # Set 3.
    Set3.challenge_17()
    Set3.challenge_18()


def main():
    print("\n\n-- The Cryptopals Crypto Challenges in Python by ABP --")
    # https://cryptopals.com
    startTime = time.time()

    # Profiling stat options.
    '''# function_stats('set_1.challenge_4()')
    print(sys.path)'''

    run_challenges()

    executionTime = (time.time() - startTime)
    print(f'\nExecution time in seconds: {executionTime}')


if __name__ == "__main__":
    main()
