#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import datetime
import idna
import os


def now(offset=0):
    time_now = datetime.datetime.now()
    time_now += datetime.timedelta(seconds=offset)
    return time_now.strftime("%Y-%m-%d %H:%M:%S")


def puny_to_utf8(name):
    try:
        idn = idna.decode(name)
        return idn
    except idna.IDNAError:
        try:
            idn = name.encode("utf-8").decode("idna")
            return idn
        except UnicodeError:
            return None
    return None


def utf8_to_puny(utf8):
    try:
        puny = idna.encode(utf8)
        return puny.decode("utf-8")
    except idna.IDNAError:
        try:
            puny = utf8.encode("idna")
            return puny.decode("utf-8")
        except UnicodeError:
            return None
    return None


def debug_mode():
    return os.environ.get("DEBUG_MODE", "N") == "Y"


if __name__ == "__main__":
    for x in ["xn--belgi-rsa.be", "xn--9q8h.ss-test-1", "fred.com"]:
        utf8 = puny_to_utf8(x)
        print(x, "->", utf8)
        puny = utf8_to_puny(utf8)
        print(utf8, "->", puny)
