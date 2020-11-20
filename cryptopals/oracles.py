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
