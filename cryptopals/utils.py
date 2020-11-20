from pathlib import Path

# note to self find that data file you forgot about!!! Pretty sure it was encrypted in AES not sure if it was CBC mode or ECBmode though.
# No idea what the passwordpassword was, think I know it was 16 characters though and something simple. I remember I wrote some extra
# functions for this kind of thing in the oracle.py file.


def hex2bytes(hex_ciphertext):
    return bytes.fromhex(hex_ciphertext)


def import_data(file_name):
    file_path = str(Path(__file__).parent.resolve() / "data/" / file_name)
    with open(file_path) as f:
        return f.read()


def encode(text):
    return text.encode("utf-8")


def decode(byte_array):
    return byte_array.decode("utf-8")
