#!/usr/bin/env python
"""
IP-format-preserving encryption

Can be used to "anonymize" logs, etc.

This uses a new 4-byte-block cipher, inspired from SipHash.

Takes some file.csv, writes to stdout.
IPs are assumed encoded as X.Y.Z.T
FIELD is the index of the IP in a CSV, starting from 0.
KEY is a 16-byte secret key,

Copyright (c) 2015 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
Under CC0 license <http://creativecommons.org/publicdomain/zero/1.0/>
"""

import csv
import struct
import sys


FIELD = 0        # index of the IP in the CSV files
KEY = '\xff'*16  # copy your key here
DELIMITER = ','  # CSV delimiter character


def rotl(b, r):
    return ((b << r) & 0xff) | (b >> (8 - r))


def permute_fwd(state):
    (b0, b1, b2, b3) = state
    b0 += b1
    b2 += b3
    b0 &= 0xff
    b2 &= 0xff
    b1 = rotl(b1, 2)
    b3 = rotl(b3, 5)
    b1 ^= b0
    b3 ^= b2
    b0 = rotl(b0, 4)
    b0 += b3
    b2 += b1
    b0 &= 0xff
    b2 &= 0xff
    b1 = rotl(b1, 3)
    b3 = rotl(b3, 7)
    b1 ^= b2
    b3 ^= b0
    b2 = rotl(b2, 4)
    return (b0, b1, b2, b3)


def permute_bwd(state):
    (b0, b1, b2, b3) = state
    b2 = rotl(b2, 4)
    b1 ^= b2
    b3 ^= b0
    b1 = rotl(b1, 5)
    b3 = rotl(b3, 1)
    b0 -= b3
    b2 -= b1
    b0 &= 0xff
    b2 &= 0xff
    b0 = rotl(b0, 4)
    b1 ^= b0
    b3 ^= b2
    b1 = rotl(b1, 6)
    b3 = rotl(b3, 3)
    b0 -= b1
    b2 -= b3
    b0 &= 0xff
    b2 &= 0xff
    return (b0, b1, b2, b3)


def xor4(x, y):
    return [(x[i] ^ y[i]) & 0xff for i in (0, 1, 2, 3)]


def encrypt(key, ip):
    """16-byte key, ip string like '192.168.1.2'"""
    k = [struct.unpack('<B', x)[0] for x in key]
    state = [int(x) for x in ip.split('.')]
    state = xor4(state, k[:4])
    state = permute_fwd(state)
    state = xor4(state, k[4:8])
    state = permute_fwd(state)
    state = xor4(state, k[8:12])
    state = permute_fwd(state)
    state = xor4(state, k[12:16])
    return '.'.join(str(x) for x in state)


def decrypt(key, ip):
    """16-byte key, encrypted ip string like '215.51.199.127'"""
    k = [struct.unpack('<B', x)[0] for x in key]
    state = [int(x) for x in ip.split('.')]
    state = xor4(state, k[12:16])
    state = permute_bwd(state)
    state = xor4(state, k[8:12])
    state = permute_bwd(state)
    state = xor4(state, k[4:8])
    state = permute_bwd(state)
    state = xor4(state, k[:4])
    return '.'.join(str(x) for x in state)


def usage():
    print 'usage:  %s csvfile e|d' % sys.argv[0]
    print '\te = encrypt, d = decrypt'
    sys.exit(0)


def test():
    """basic encryption sanity check"""
    ip = init = '1.2.3.4'
    iterations = 100
    for i in xrange(iterations):
        ip = encrypt(KEY, ip)
    for i in xrange(iterations):
        ip = decrypt(KEY, ip)
    if ip != init:
        raise ValueError


def main():
    assert len(KEY) == 16
    try:
        test()
    except ValueError:
        print 'test failed'
        sys.exit(0)

    try:
        filein = sys.argv[1]
        mode = sys.argv[2]
    except IndexError:
        usage()

    if mode == 'e':
        process = encrypt
    elif mode == 'd':
        process = decrypt
    else:
        usage()

    with open(filein, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=DELIMITER)
        writer = csv.writer(sys.stdout, delimiter=DELIMITER)

        for row in reader:
            ip = row[FIELD].strip()
            newrow = row
            newrow[FIELD] = process(KEY, ip)
            writer.writerow(newrow)


if __name__ == '__main__':
    sys.exit(main())
