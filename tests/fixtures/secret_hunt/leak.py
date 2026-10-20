"""Deliberately leaky config used by the round-6 scan fixture.

EVERY credential here is fake and was generated for the test. Never put real
values in this file; the scan fixture depends on finding all of them.
"""
from __future__ import annotations

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
SLACK_TOKEN = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
STRIPE_KEY = "sk_live_51H8x2KjH8x2KjH8x2KjH8x2KjH8x2KjH8"
GOOGLE_API_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu"
AUTHORIZATION = "Bearer abcdefghijklmnopqrstuvwxyz012345"
DATABASE_URL = "postgres://admin:hunter2@db.internal:5432/app"
PASSWORD = "correct-horse-battery-staple"
ENCRYPTION_KEY = "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a"

SESSION_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF1P6n9Q1q2r3t4u5v6w7x8y9z0ab
-----END RSA PRIVATE KEY-----"""
