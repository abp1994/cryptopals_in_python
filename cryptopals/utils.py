import cProfile
import os
import pstats
import sys
from pathlib import Path


def blockPrint():
    sys.stdout = open(os.devnull, 'w')


def enablePrint():
    sys.stdout = sys.__stdout__


def import_data(file_name):
    file_path = str(Path(__file__).parent.resolve() / "data/" / file_name)
    with open(file_path) as f:
        return f.read()


def encode(text):
    return text.encode("utf-8")


def decode(byte_array):
    return byte_array.decode("utf-8", errors='ignore')


def function_stats(function):
    profile = cProfile.Profile()
    ut.blockPrint()
    profile.run(function)
    ut.enablePrint()
    ps = pstats.Stats(profile)
    ps.print_stats()
