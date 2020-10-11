import secrets
import sys
from base64 import b64decode
from pathlib import Path

import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.append(str(Path(__file__).parent.resolve()))
from dataclasses import dataclass

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
            output_message += iv
        return output_message

    def decrypt(self, data):
        iv = self.iv
        output_message = b""
        input_message = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
        for block in input_message:
            step_1 = AESECB(self.key).decrypt(block)
            output_message += bo.xor(iv, step_1)
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
        self.random_prefix = secrets.token_bytes(secrets.randbelow(16) + 16)
        self.oracle = C12()

    def encrypt(self, user_bytes):
        combination = b''.join([self.random_prefix, user_bytes])
        return self.oracle.encrypt(combination)


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
            raise StopIteration("Indeterminable block size")
    block_size = output_size - initial_output_size
    position_in_block = block_size - len(bytestring)
    return block_size, position_in_block


class Profiler:
    """Functions used to profile an encryption oracle"""
    def __init__(self, oracle):
        self.oracle = oracle
        self.model_output = oracle.encrypt(b"")
        self.model_size = len(self.model_output)

        self.mode = self.mode_check()
        self.block_size, self.input_index = self.find_block_size()

    def mode_check(self):
        data = self.oracle.encrypt(b"0" * 50)
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
            bytestring += b"0"
            output_size = len(self.oracle.encrypt(bytestring))

            # Clause for no solution found.
            if 100 < len(bytestring):
                raise StopIteration("Indeterminable block size")

        # Determine change in size of output and input byte position in block
        block_size = output_size - self.model_size
        index_in_block = block_size - len(bytestring)

        return block_size, index_in_block
