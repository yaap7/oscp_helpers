#!/usr/bin/env python3

import sys
import binascii


def main():
    payload = sys.stdin.buffer.read()
    print(''.join('\\x{:02x}'.format(x) for x in payload))
    print()
    print(binascii.hexlify(bytearray(payload)).decode('ascii'))


if __name__ == "__main__":
    main()
