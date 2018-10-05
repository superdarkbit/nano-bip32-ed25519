'''
Thank you Vincent Bernardoff and "cincrement" for your work which this is based off of: https://github.com/vbmithr/ocaml-bip32-ed25519/blob/master/test/test_vectors/make-bip32-ed25519-test-vectors.py

Copyright (c) 2017 Vincent Bernardoff

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''


import hmac
import hashlib
import secrets
import ed25519

def h512(m):
    #return hashlib.sha512(m).digest()
    return hashlib.blake2b(m).digest()

def h256(m):
    return hashlib.sha256(m).digest()

def Fk(message, secret):
    return hmac.new(secret, message, hashlib.sha512).digest()

def set_bit(character, pattern):
    return character | pattern

def clear_bit(character, pattern):
    return character & ~pattern

def root_key(master_secret):
    if type(master_secret) is not bytes:
        raise Exception("master_secret must be of type 'bytes'")
    if len(master_secret) != 32:
        raise Exception("master_secret must be 32 bytes (256-bits)")
    k = bytearray(h512(master_secret))
    kL, kR = k[:32], k[32:]

    if kL[31] & 0b00100000:
        return None

    # clear lowest three bits of the first byte
    kL[0]  = clear_bit( kL[0], 0b00000111)
    # clear highest bit of the last byte
    kL[31] = clear_bit(kL[31], 0b10000000)
    # set second highest bit of the last byte
    kL[31] =   set_bit(kL[31], 0b01000000)

    # root public key
    A = ed25519.encodepoint(ed25519.scalarmultbase(int.from_bytes(kL, 'little')))
    # root chain code
    c = h256(b'\x01' + master_secret)
    return ((kL, kR), A, c)

def private_child_key(node, i):
    if not node:
        return None
    # unpack argument
    ((kLP, kRP), AP, cP) = node
    assert 0 <= i < 2**32

    i_bytes = i.to_bytes(4, 'little')
    if i < 2**31:
        # regular child
        Z = Fk(b'\x02' + AP + i_bytes, cP)
        c = Fk(b'\x03' + AP + i_bytes, cP)[32:]
    else:
        # hardened child
        Z = Fk(b'\x00' + (kLP + kRP) + i_bytes, cP)
        c = Fk(b'\x01' + (kLP + kRP) + i_bytes, cP)[32:]

    ZL, ZR = Z[:28], Z[32:]

    kLn = (int.from_bytes(ZL, 'little') * 8) + int.from_bytes(kLP, 'little')
    # "If kL is divisible by the base order n, discard the child."
    # - "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
    if kLn % ed25519.l == 0:
        return -1
    kRn = (
        int.from_bytes(ZR, 'little') + int.from_bytes(kRP, 'little')
    ) % 2**256
    kL = kLn.to_bytes(32, 'little')
    kR = kRn.to_bytes(32, 'little')

    A = ed25519.encodepoint(ed25519.scalarmultbase(int.from_bytes(kL, 'little')))
    return ((kL, kR), A, c)

def safe_public_child_key(extended_public_key, chain_code, i, return_as_hex=True):
    if not extended_public_key or not chain_code:
        return None
    AP = extended_public_key
    cP = chain_code
    assert 0 <= i < 2**31

    i_bytes = i.to_bytes(4, 'little')
    if i < 2**31:
        # regular, non-hardened child
        Z = Fk(b'\x02' + AP + i_bytes, cP)
        c = Fk(b'\x03' + AP + i_bytes, cP)[32:]
    else:
        raise Exception("Can't create hardened keys from public key")

    ZL, ZR = Z[:28], Z[32:]

    A = ed25519.encodepoint(
        ed25519.edwards(ed25519.decodepoint(AP), ed25519.scalarmultbase(8 * int.from_bytes(ZL, 'little')))
    )

    # VERY IMPORTANT. DO NOT USE A CHILD KEY THAT IS EQUIVALENT TO THE IDENTITY POINT
    # "If Ai is the identity point (0, 1), discard the child."
    # - "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
    if A == ed25519.encodepoint([0, 1]):
        return -1

    if return_as_hex:
        return (A.hex(), c.hex())
    else:
        return (A, c)

def special_signing(kL, kR, A, M): # private/secret key left and right sides kL & kR, public key A, and message M in bytes
    r = h512(kR + M)

    r = int.from_bytes(r, 'little') % ed25519.l # base order n
    R = ed25519.encodepoint(ed25519.scalarmultbase(r))
    x = int.from_bytes(h512(R+A+M), 'little')
    S = ed25519.encodeint((r + (x * int.from_bytes(kL, 'little'))) % ed25519.l)
    return R+S

# "Let k_tilde be 256-bit master secret. Then derive k = H512(k_tilde)
# and denote its left 32-byte by kL and right one by kR. If the
# third highest bit of the last byte of kL is not zero, discard k_tilde"
# - "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
def generate_proper_master_secret():

    while True:
        master_secret = secrets.token_bytes(32)
        k = bytearray(h512(master_secret))
        kL = k[:32]

        if not(kL[31] & 0b00100000):
            break

    return master_secret

def derive_chain(master_secret, chain):
    root = root_key(master_secret)
    node = root

    for i in chain.split('/'):
        if not i:
            continue
        if i.endswith("'"):
            i = int(i[:-1]) + 2**31
        else:
            i = int(i)
        node = private_child_key(node, i)
    return node
