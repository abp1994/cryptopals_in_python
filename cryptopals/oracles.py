import secrets
import sys
from base64 import b64decode
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.append(str(Path(__file__).parent.resolve()))
import byte_operations as bo
import utils as ut
from utils import decode, encode


class AESECB:
    def __init__(self, key):
        self.cipher = Cipher(algorithms.AES(key),
                             modes.ECB(),
                             backend=default_backend())

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()


class AESCBC:
    def __init__(self, iv, key):
        self.iv = iv
        self.key = key

    def encrypt(self, data):
        iv = self.iv
        output_message = b""
        input_message = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
        for block in input_message:
            step_1 = bo.xor(iv, block)
            iv = AESECB(self.key).encrypt(step_1)
            output_message = b"".join([output_message, iv])
        return output_message

    def decrypt(self, data):
        iv = self.iv
        output_message = b""
        input_message = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
        for block in input_message:
            step_1 = AESECB(self.key).decrypt(block)
            output_message = b"".join([output_message, bo.xor(iv, step_1)])
            iv = block
        return output_message


class C11:
    def __init__(self):
        self.mode = secrets.choice(["ECB", "CBC"])
        self.key = bo.random_AES_key()
        self.iv = secrets.token_bytes(16)

    def encrypt(self, data):
        data = secrets.token_bytes(
            secrets.randbelow(5)) + data + secrets.token_bytes(
                secrets.randbelow(5))
        data_padded = bo.pad(16, data)
        if self.mode == "ECB":
            result = AESECB(self.key).encrypt(data_padded)
        else:
            result = AESCBC(self.iv, self.key).encrypt(data_padded)
        return result


class C12:
    def __init__(self):
        self.key = bo.random_AES_key()
        self.secret = b64decode(ut.import_data("data_S2C12.txt"))

    def encrypt(self, prepend):
        data = bo.pad(16, prepend + self.secret)
        return AESECB(self.key).encrypt(data)


class C14:
    def __init__(self):
        self.random_prefix = secrets.token_bytes(secrets.randbelow(64) + 1)
        self.oracle = C12()

    def encrypt(self, user_bytes):
        combination = b"".join([self.random_prefix, user_bytes])
        return self.oracle.encrypt(combination)


class C16:
    def __init__(self):
        self.iv = bo.random_AES_key()
        self.key = bo.random_AES_key()
        self.prefix = b"comment1=cooking%20MCs;userdata="
        self.suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(self, user_bytes):
        user_string = decode(user_bytes)
        clean_user_string = user_string.replace(";", '";"').replace("=", '"="')
        byte_string = b"".join(
            [self.prefix, encode(clean_user_string), self.suffix])
        data = bo.pad(16, byte_string)
        return AESCBC(self.iv, self.key).encrypt(data)

    def decrypt(self, bytes):
        data = decode(AESCBC(self.iv, self.key).decrypt(bytes))
        return [tuple(pair.split('=', 1)) for pair in data.split(';')]

    def check_admin(self, bytes):
        decrypted_fields = self.decrypt(bytes)
        return ("admin", "true") in decrypted_fields


def profile_create(email):
    data = profile_parse(email)
    padded_data = bo.pad(16, data)
    return AESECB(b"PASSWORDPASSWORD").encrypt(padded_data)


def profile_parse(email):
    if 0 < sum(map(email.count, ("=", "&"))):
        raise Exception("Invalid character encountered")
    return encode(f"email={email}&uid=10&role=user")


def profile_decrypt(data):
    return AESECB(b"PASSWORDPASSWORD").decrypt(data)


def profile_unpack(data):
    return {
        decode(key): decode(value)
        for key, value in (line.split(b"=") for line in data.split(b"&"))
    }


def ECB_check(oracle):
    data = oracle.encrypt(b"Z" * 50)
    blocks = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
    duplicate_blocks = len(blocks) - len(np.unique(blocks, axis=0))
    return True if 0 < duplicate_blocks else False


# Functions used to profile an encryption oracle.
class Profiler:
    def __init__(self, oracle):
        self.oracle = oracle
        self.model_output = oracle.encrypt(b"")
        self.model_size = len(self.model_output)

        self.mode = self.mode_check()
        self.block_size, self.initial_pad_size = self.find_block_size()
        if self.mode == "ECB":
            self.input_byte_index = self.find_input_byte_index(self.block_size)
            self.input_block_index = self.input_byte_index // self.block_size
        else:
            self.input_byte_index = None
            self.input_block_index = None

    def mode_check(self):
        data = self.oracle.encrypt(b"Z" * 50)
        blocks = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
        duplicate_blocks = len(blocks) - len(np.unique(blocks, axis=0))
        return "ECB" if 0 < duplicate_blocks else "Not ECB"

    def find_block_size(self):
        # Encrypt increasingly long byte strings using the oracle until
        # output changes size. Return change in size of output.

        # Initialise variables.
        output_size = self.model_size
        bytestring = b""

        # Loop while output size remains unchanged.
        while output_size == self.model_size:

            # Increase input length by one byte.
            bytestring = b"".join([bytestring, b"Z"])
            output_size = len(self.oracle.encrypt(bytestring))

            # Clause for no solution found.
            if 256 < len(bytestring):
                raise StopIteration("Indeterminable block size")

        # Determine change in size of output and input byte position in block.
        block_size = output_size - self.model_size
        initial_pad_size = len(bytestring)
        if initial_pad_size == 0:
            initial_pad_size = 16

        return block_size, initial_pad_size

    def find_input_byte_index(self, block_size):
        # Encrypt increasingly long byte strings using the oracle until
        # 2 identical blocks are found in the output next to each other.
        # Return the index of the block that matches with a previous block.

        bytestring = b""
        duplicate_found, duplicate_block_index = bo.detect_adjacent_duplicate_blocks(
            self.oracle.encrypt(bytestring), block_size)

        while (not (duplicate_found)):

            bytestring = b"".join([bytestring, b"Z"])
            duplicate_found, duplicate_block_index = bo.detect_adjacent_duplicate_blocks(
                self.oracle.encrypt(bytestring), block_size)

            if len(bytestring) > (3 * block_size):
                raise StopIteration("Indeterminate input byte index")

        # The input byte index is found by counting backwards the number of bytes in the
        # input from the duplicate blocks' location in bytes.
        input_byte_index = (
            (duplicate_block_index + 1) * block_size) - len(bytestring)
        return input_byte_index
