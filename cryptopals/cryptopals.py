import sys
import time
from base64 import b64decode, b64encode
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.append(str(Path(__file__).parent.resolve()))
import byte_operations as bo
import oracles as ocl
import utils as ut
from utils import decode, encode


def my_code():
    # Find useful functions in the byte_operations.py file
    # and the utils.py file.
    print("\n\n-- Saran's Functions --")
    # Write your code here, the last person through here seems to have left some of theirs better clean that up! ↓↓↓
    a = ut.encode('-')
    b = ut.encode('-')
    #c = bo.
    #d = decode()

    # use me ↓
    print("Useful findings : ")
    print(a)
    return


def main():
    startTime = time.time()
    my_code()
    executionTime = (time.time() - startTime)
    print(f'\nExecution time in seconds: {executionTime}')
    print("Press return to exit.")
    input()


if __name__ == "__main__":
    main()
