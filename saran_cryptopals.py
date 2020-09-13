import base64


def s1_c1():
    hex_value = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    bytearray_value = bytearray.fromhex(hex_value)
    base64_value = base64.b64encode(bytearray_value)
    return base64_value


def s1_c2():
    hex_value = '1c0111001f010100061a024b53535009181c'
    hex_key = '686974207468652062756c6c277320657965'
    xor_value = int(hex_value, 16) ^ int(hex_key, 16)
    return hex(xor_value)


def main():
    s1_c2()


if __name__ == "__main__":
    main()
