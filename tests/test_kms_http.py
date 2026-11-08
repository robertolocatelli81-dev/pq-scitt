#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pq-scitt — tests for the stdlib-only AWS KMS backend (awskms-http).

SPDX-License-Identifier: Apache-2.0
Copyright (C) 2026 Roberto Locatelli

Self-contained (no external deps, no credentials): validates the SigV4 signing-key
against AWS's official test vector and the URI/honesty behaviour. The live round-trip
against real AWS KMS is exercised separately (needs an account + credentials).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pq_scitt import kms as k  # noqa: E402


class TestSigV4Vector(unittest.TestCase):
    def test_signing_key_matches_official_aws_vector(self):
        got = k._sigv4_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam").hex()
        self.assertEqual(
            got, "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")


class TestUriAndHonesty(unittest.TestCase):
    def test_requires_key_id_and_region(self):
        with self.assertRaises(ValueError):
            k.backend_from_uri("awskms-http:key_id=abc")            # region missing
        with self.assertRaises(ValueError):
            k.backend_from_uri("awskms-http:region=eu-north-1")     # key_id missing

    def test_honest_without_credentials(self):
        saved = {kk: os.environ.pop(kk, None)
                 for kk in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
        try:
            with self.assertRaises(RuntimeError):
                k.backend_from_uri("awskms-http:key_id=abc;region=eu-north-1")
        finally:
            for kk, v in saved.items():
                if v is not None:
                    os.environ[kk] = v

    def test_legacy_awskms_backend_untouched(self):
        # the pre-existing boto3 backend stays available (nothing removed)
        self.assertTrue(hasattr(k, "AwsKmsBackend"))
        self.assertTrue(hasattr(k, "AwsKmsHttpBackend"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
