#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import base64

import base58
import pysodium
from clk.decorators import argument, group
from clk.log import get_logger
from pyblake2 import blake2b

LOGGER = get_logger(__name__)


def tb(data):
    return b"".join(map(lambda x: x.to_bytes(1, "big"), data))


@group()
def tezos():
    "Commands to play with tezos"


def compute_address(public_key):
    pkh = blake2b(data=public_key, digest_size=20).digest()
    # tz1
    return base58.b58encode_check(tb([6, 161, 159]) + pkh).decode()


@tezos.command()
@argument("publickeyb64", help="The base64 representation of the public key")
def _compute_address(publickeyb64):
    "Compute some tezos address, provided the public key"
    public_key = base64.b64decode(publickeyb64.encode())
    print(compute_address(public_key))


def encode_signature(message):
    # sig
    return base58.b58encode_check(tb([4, 130, 43]) + message).decode()


def digest(messageb64):
    message = base64.b64decode(messageb64.encode())
    return base64.b64encode(pysodium.crypto_generichash(message)).decode()


@tezos.command()
@argument("publickeyb64", help="The base64 representation of the public key")
def compute_public_key(publickeyb64):
    "Compute the public key in a format that tezos understands"
    public_key = base64.b64decode(publickeyb64.encode())
    print(base58.b58encode_check(tb([13, 15, 37, 217]) + public_key).decode())


@tezos.command()
@argument("messageb64", help="The message encoded in base64")
def _digest(messageb64):
    """Compute the digest to sign, provided the (forged) message"""
    print(digest(messageb64))
