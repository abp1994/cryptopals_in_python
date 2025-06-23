import cProfile
import os
import pstats
import sys
from pathlib import Path

import utils as ut


def enable_print():
    sys.stdout = sys.__stdout__


def disable_print():
    sys.stdout = open(os.devnull, "w")


def import_data(file_name):
    file_path = str(Path(__file__).parent.resolve() / "data/" / file_name)
    with open(file_path) as f:
        return f.read()


def encode(text):
    return text.encode("utf-8")


def decode(byte_array):
    return byte_array.decode("utf-8", errors="ignore")


def function_stats(function):
    profile = cProfile.Profile()
    ut.disable_print()
    profile.run(function)
    ut.enable_print()
    ps = pstats.Stats(profile)
    ps.print_stats()
