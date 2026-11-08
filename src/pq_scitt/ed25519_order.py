#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""Ed25519 points of small and mixed order (0.21.0), standard library only.

RFC 8032 5.1.7 lets a verifier use the cofactorless or the cofactored equation; libraries differ on keys and R values
outside the subgroup of order L. Measured 14/10/2026 on the 12 classes of novifinancial/ed25519-speccheck rebuilt on
ledger entries: OpenSSL through `cryptography` (signer.py of cryptovalid-opencore), Node, Go's crypto/ed25519 and swift-crypto verified six of
them (a key or an R of small order, a key of mixed order, a key with x = 0 and the sign bit set), the JDK four. The x402
acceptance checker of the same author refuses all 12 (b37e471). The Ed25519 checks of the four verifiers that verify
signatures (JS, Go, Java, Swift) and of cryptovalid-opencore's signer.py now apply these rules before the library's equation:

- the public key decodes as RFC 8032 5.1.3 says (y < p; x = 0 with the sign bit set refused), is not of small order
  ([8]A is not the neutral point) and lies in the subgroup of order L ([L]A is the neutral point);
- R decodes the same way and is not of small order. An R of mixed order needs no check: with A in the subgroup,
  S*B = R + k*A puts R in it too, so the cofactorless equation every library here uses refuses it (class 4, 5, 13).

One scalar multiplication by L per distinct key (callers cache it), three doublings per R. Written from RFC 8032 5.1
(constants, 5.1.3 decoding, 5.1.4 addition). Not constant time: public values only."""
p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493   # the order of the base point (RFC 8032 section 3)
d = (-121665 * pow(121666, p - 2, p)) % p
_I = pow(2, (p - 1) // 4, p)
NEUTRAL = (0, 1, 1, 0)


def decode(enc):
    """RFC 8032 5.1.3: extended coordinates, or None when the 32 octets are not a point."""
    if not isinstance(enc, (bytes, bytearray)) or len(enc) != 32:
        return None
    n = int.from_bytes(bytes(enc), "little")
    x_0, y = n >> 255, n & ((1 << 255) - 1)
    if y >= p:
        return None
    u, v = (y * y - 1) % p, (d * y * y + 1) % p
    x = u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p) % p
    vxx = v * x * x % p
    if vxx == u:
        pass
    elif vxx == (-u) % p:
        x = x * _I % p
    else:
        return None
    if x == 0 and x_0 == 1:
        return None
    if x % 2 != x_0:
        x = p - x
    return (x, y, 1, x * y % p)


def encode(P):
    X, Y, Z, _ = P
    zi = pow(Z, p - 2, p)
    x, y = X * zi % p, Y * zi % p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def add(P1, P2):
    """RFC 8032 5.1.4."""
    X1, Y1, Z1, T1 = P1
    X2, Y2, Z2, T2 = P2
    a, b = (Y1 - X1) * (Y2 - X2) % p, (Y1 + X1) * (Y2 + X2) % p
    c, dd = T1 * 2 * d * T2 % p, Z1 * 2 * Z2 % p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def scalar_mul(k, P):
    R = NEUTRAL
    for i in range(k.bit_length() - 1, -1, -1):
        R = add(R, R)
        if (k >> i) & 1:
            R = add(R, P)
    return R


def is_neutral(P):
    X, Y, Z, _ = P
    return X % p == 0 and (Y - Z) % p == 0


def key_problem(pub):
    """None when the 32-octet key is usable; else key_not_decodable, small_order_key or mixed_order_key."""
    A = decode(pub)
    if A is None:
        return "key_not_decodable"
    if is_neutral(scalar_mul(8, A)):
        return "small_order_key"
    if not is_neutral(scalar_mul(L, A)):
        return "mixed_order_key"
    return None


def r_problem(sig):
    """None when R (the first 32 octets of a 64-octet signature) decodes and is not of small order."""
    R = decode(bytes(sig[:32])) if isinstance(sig, (bytes, bytearray)) and len(sig) == 64 else None
    if R is None:
        return "r_not_decodable"
    return "small_order_r" if is_neutral(scalar_mul(8, R)) else None


def strict_problem(pub, sig, key_cache=None):
    """The first of key_problem / r_problem that applies, or None; key_cache (a dict) memoises key_problem."""
    if key_cache is not None and bytes(pub) in key_cache:
        kp = key_cache[bytes(pub)]
    else:
        kp = key_problem(pub)
        if key_cache is not None:
            key_cache[bytes(pub)] = kp
    return kp or r_problem(sig)
