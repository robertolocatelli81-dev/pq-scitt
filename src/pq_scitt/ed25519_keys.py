#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pq_scitt/ed25519_keys.py — single check of the Ed25519 keys and signatures that come from outside (07/11/2026).

Measured (audit 07/11, §0): with key = neutral point, R = neutral, S = 0, the `cryptography` library accepts ANY
message; it also accepts keys of order 2 and non-canonical keys. RFC 8032 §5.1.7 leaves the equation open: the checks
must be done first. Uses `pq_scitt/ed25519_order.py` (same code as release 0.21.0 of cryptovalid-opencore).

Cost: one scalar multiplication by L per key (pure Python, public values); keys already seen are cached.
Results: None if fine, otherwise key_not_decodable, small_order_key, mixed_order_key, r_not_decodable, small_order_r.
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import Optional

# Dependency: `pq_scitt/ed25519_order.py` (stdlib only), in the same package. The except branches below come from the
# original code: here they all import the same package module.
try:
    from pq_scitt import ed25519_order as _order
except ImportError:   # original branch
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from pq_scitt import ed25519_order as _order
    except ImportError:
        try:
            from pq_scitt import ed25519_order as _order   # original branch: here it is the same module
        except ImportError:
            raise ImportError("pq_scitt/ed25519_keys.py requires pq_scitt/ed25519_order.py in the same package: "
                              "incomplete installation, reinstall pq-scitt") from None


@lru_cache(maxsize=4096)
def _key_problem(raw: bytes) -> Optional[str]:
    return _order.key_problem(raw)


def key_problem(raw) -> Optional[str]:
    """None if the 32 bytes are a usable public key, otherwise the reason for the rejection."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        return "key_not_decodable"
    return _key_problem(bytes(raw))


def signature_problem(raw_key, signature) -> Optional[str]:
    """The first defect of the key or of R, or None. It does not replace the signature check: it comes before it."""
    return key_problem(raw_key) or _order.r_problem(signature)
