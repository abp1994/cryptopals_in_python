import random
import secrets
import sys
from base64 import b64decode
from pathlib import Path
from typing import final

import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.append(str(Path(__file__).parent.resolve()))

from . import byte_operations as bo
from . import utils as ut
from .utils import decode, encode


@final
class AESECB:
    def __init__(self, key: bytes):
        self.cipher = Cipher(
            algorithms.AES(key), modes.ECB(), backend=default_backend()
        )

    def encrypt(self, plaintext: bytes):
        encryptor = self.cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes):
        decryptor = self.cipher.decryptor()
        return decryptor.update(ciphertext)


@final
class AESCBC:
    def __init__(
        self,
        iv: bytes,
        key: bytes,
    ):
        self.iv = iv
        self.key = key

    def encrypt(self, plaintext: bytes):
        iv = self.iv
        output_message = b""
        input_message = np.frombuffer(plaintext, dtype="uint8").reshape(-1, 16)
        for block in input_message:
            step_1 = bo.xor(iv, block)
            iv = AESECB(self.key).encrypt(step_1)
            output_message = b"".join([output_message, iv])
        return output_message

    def decrypt(self, ciphertext: bytes):
        iv = self.iv
        output_message = b""
        input_message = np.frombuffer(ciphertext, dtype="uint8").reshape(-1, 16)
        for block in input_message:
            step_1 = AESECB(self.key).decrypt(block)
            output_message = b"".join([output_message, bo.xor(iv, step_1)])
            iv = block
        return output_message


@final
class AESCTR:
    # Encryption/decryption using small endian nonce + counter
    def __init__(self, nonce: bytes, key: bytes):
        self.nonce = nonce
        self.key = key
        self.encryption_counter = 0
        self.decryption_counter = 0
        self.cipher = AESECB(self.key)
        self.keystream_encryption_buffer = b""
        self.keystream_decryption_buffer = b""

    def encrypt(self, plaintext: bytes):
        plaintext_size = len(plaintext)
        # Generate keystream so buffer is larger than size of plaintext.
        self.generate_keystream_buffer(plaintext_size, "encryption")

        # Xor keystream with plaintext.
        keystream = self.keystream_encryption_buffer[:plaintext_size]
        ciphertext = bo.xor(keystream, plaintext)

        # Remove xored bytes from keystream buffer.
        self.keystream_encryption_buffer = self.keystream_encryption_buffer[
            plaintext_size:
        ]

        return ciphertext

    def decrypt(self, ciphertext: bytes):
        ciphertext_size = len(ciphertext)
        # Generate keystream so buffer is larger than size of ciphertext.
        self.generate_keystream_buffer(ciphertext_size, "decryption")

        # Xor keystream with ciphertext.
        keystream = self.keystream_decryption_buffer[:ciphertext_size]
        plaintext = bo.xor(keystream, ciphertext)

        # Remove xored bytes from keystream buffer.
        self.keystream_decryption_buffer = self.keystream_decryption_buffer[
            ciphertext_size:
        ]

        return plaintext

    def generate_keystream_buffer(self, desired_size: int, mode: str):
        if mode == "encryption":
            buffer_size = len(self.keystream_encryption_buffer)
        else:
            buffer_size = len(self.keystream_decryption_buffer)

        while buffer_size < desired_size:
            if mode == "encryption":
                count = self.encryption_counter.to_bytes(8, byteorder="little")
                self.encryption_counter += 1
            else:
                count = self.decryption_counter.to_bytes(8, byteorder="little")
                self.decryption_counter += 1
            buffer_size += 1

            concatenated_nonce_and_counter = b"".join([self.nonce, count])

            keystream = self.cipher.encrypt(concatenated_nonce_and_counter)
            if mode == "encryption":
                self.keystream_encryption_buffer = b"".join(
                    [self.keystream_encryption_buffer, keystream]
                )
            else:
                self.keystream_decryption_buffer = b"".join(
                    [self.keystream_decryption_buffer, keystream]
                )


@final
class C11:
    def __init__(self):
        self.mode = secrets.choice(["ECB", "CBC"])
        self.key = bo.random_AES_key()
        self.iv = secrets.token_bytes(16)

    def encrypt(self, data: bytes):
        data = (
            secrets.token_bytes(secrets.randbelow(5))
            + data
            + secrets.token_bytes(secrets.randbelow(5))
        )
        data_padded = bo.pad(16, data)
        if self.mode == "ECB":
            result = AESECB(self.key).encrypt(data_padded)
        else:
            result = AESCBC(self.iv, self.key).encrypt(data_padded)
        return result


@final
class C12:
    def __init__(self):
        self.key = bo.random_AES_key()
        self.secret = b64decode(ut.import_data("data_S2C12.txt"))

    def encrypt(self, prefix: bytes):
        data = bo.pad(16, prefix + self.secret)
        return AESECB(self.key).encrypt(data)


class C13:
    @staticmethod
    def create_profile(email: str):
        data = C13.parse_profile(email)
        padded_data = bo.pad(16, data)
        return AESECB(b"PASSWORDPASSWORD").encrypt(padded_data)

    @staticmethod
    def parse_profile(email: str):
        if 0 < sum(map(email.count, ("=", "&"))):
            raise Exception("Invalid character encountered")
        return encode(f"email={email}&uid=10&role=user")

    @staticmethod
    def decrypt_profile(data: bytes):
        return AESECB(b"PASSWORDPASSWORD").decrypt(data)

    @staticmethod
    def unpack_profile(data: bytes):
        return {
            decode(key): decode(value)
            for key, value in (line.split(b"=") for line in data.split(b"&"))
        }


@final
class C14:
    def __init__(self):
        self.random_prefix = secrets.token_bytes(secrets.randbelow(64) + 1)
        self.oracle = C12()

    def encrypt(self, user_bytes: bytes):
        combination = b"".join([self.random_prefix, user_bytes])
        return self.oracle.encrypt(combination)


@final
class C16:
    def __init__(self):
        self.iv = bo.random_AES_key()
        self.key = bo.random_AES_key()
        self.prefix = b"comment1=cooking%20MCs;userdata="
        self.suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(self, user_bytes: bytes):
        user_string = decode(user_bytes)
        clean_user_string = user_string.replace(";", '";"').replace("=", '"="')
        byte_string = b"".join([self.prefix, encode(clean_user_string), self.suffix])
        data = bo.pad(16, byte_string)
        return AESCBC(self.iv, self.key).encrypt(data)

    def decrypt(self, bytes: bytes):
        data = decode(AESCBC(self.iv, self.key).decrypt(bytes))
        return [tuple(pair.split("=", 1)) for pair in data.split(";")]

    def is_admin(self, bytes: bytes):
        decrypted_fields = self.decrypt(bytes)
        return ("admin", "true") in decrypted_fields


@final
class C17:
    def __init__(self):
        self.iv = bo.random_AES_key()
        self.key = bo.random_AES_key()

        file_name = "data_S3C17.txt"
        self.data = b64decode(random.choice(ut.import_data(file_name).splitlines()))

    def encrypt(self):
        data = bo.pad(16, self.data)
        ciphertext = AESCBC(self.iv, self.key).encrypt(data)
        return ciphertext, self.iv

    def depad_possible(self, bytes: bytes, iv: bytes):
        data = AESCBC(iv, self.key).decrypt(bytes)
        # Try depadding data catch error.
        try:
            _ = bo.depad(data)
            outcome = True
        except ValueError:
            outcome = False

        return outcome

    def reveal(self):
        return bo.pad(16, self.data)


# Functions used to profile an encryption oracle.
@final
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

    def find_input_byte_index(self, block_size: int):
        # Encrypt increasingly long byte strings using the oracle until
        # 2 identical blocks are found in the output next to each other.
        # Return the index of the block that matches with a previous block.

        bytestring = b""
        duplicate_found, duplicate_block_index = bo.detect_adjacent_duplicate_blocks(
            self.oracle.encrypt(bytestring), block_size
        )

        while not (duplicate_found):
            bytestring = b"".join([bytestring, b"Z"])
            duplicate_found, duplicate_block_index = (
                bo.detect_adjacent_duplicate_blocks(
                    self.oracle.encrypt(bytestring), block_size
                )
            )

            if len(bytestring) > (3 * block_size):
                raise StopIteration("Indeterminate input byte index")

        # The input byte index is found by counting backwards the number of bytes in the
        # input from the duplicate blocks' location in bytes.
        input_byte_index = ((duplicate_block_index + 1) * block_size) - len(bytestring)
        return input_byte_index
