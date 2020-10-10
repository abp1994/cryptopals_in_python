import secrets
import sys
from base64 import b64decode
from pathlib import Path

import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.append(str(Path(__file__).parent.resolve()))
import byte_operations as bo
import utils as ut
from utils import decode, encode


class AES_ECB:
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


class AES_CBC:
    def __init__(self, iv, key):
        self.iv = iv
        self.key = key

    def encrypt(self, data):
        iv = self.iv
        output_message = b""
        input_message = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
        for block in input_message:
            step_1 = bo.xor(iv, block)
            iv = AES_ECB(self.key).encrypt(step_1)
            output_message += iv
        return output_message

    def decrypt(self, data):
        iv = self.iv
        output_message = b""
        input_message = np.frombuffer(data, dtype="uint8").reshape(-1, 16)
        for block in input_message:
            step_1 = AES_ECB(self.key).decrypt(block)
            output_message += bo.xor(iv, step_1)
            iv = block
        return output_message


class C11:
    def encrypt(self, data):
        data = secrets.token_bytes(
            secrets.randbelow(5)) + data + secrets.token_bytes(
                secrets.randbelow(5))
        data_padded = bo.pad(16, data)
        if secrets.choice([True, False]):
            mode = "ECB"
            result = AES_ECB(bo.random_AES_key()).encrypt(data_padded)
        else:
            mode = "CBC"
            result = AES_CBC(secrets.token_bytes(16),
                             bo.random_AES_key()).encrypt(data_padded)
        print(f"Oracle mode used   : {mode}")
        return result


class C12:
    def __init__(self):
        self.key = bo.random_AES_key()
        self.secret = b64decode(ut.import_data("data_S2C12.txt"))

    def encrypt(self, prepend):
        data = bo.pad(16, prepend + self.secret)
        return AES_ECB(self.key).encrypt(data)


def profile_create(email):
    data = profile_parse(email)
    padded_data = bo.pad(16, data)
    return AES_ECB(b"PASSWORDPASSWORD").encrypt(padded_data)


def profile_parse(email):
    if 0 < sum(map(email.count, ("=", "&"))):
        raise Exception("Invalid character encountered")
    return encode(f"email={email}&uid=10&role=user")


def profile_decrypt(data):
    return AES_ECB(b"PASSWORDPASSWORD").decrypt(data)


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
    return output_size - initial_output_size
