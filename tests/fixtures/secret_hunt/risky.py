"""Deliberately unsafe code for the round-6 pattern fixture.

None of this is copied from real code; it exists so the pattern rules have
something correct to find.
"""
from __future__ import annotations

import hashlib
import os
import pickle
import random
import ssl
import subprocess

import yaml


def load_config(raw: str):
    return yaml.load(raw)


def run(cmd: str) -> None:
    subprocess.run(cmd, shell=True)
    os.system(cmd)


def digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def unmarshal(blob: bytes):
    return pickle.loads(blob)


def insecure_client():
    return ssl._create_unverified_context()


def fetch(url: str):
    import requests
    return requests.get(url, verify=False)


def make_token() -> str:
    return str(random.random())


def lookup(conn, user: str):
    return conn.execute(f"SELECT * FROM users WHERE name = '{user}'")


def handle(user_input: str):
    return eval(user_input)
