#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import datetime
import idna

import policy


def now(offset=0):
    time_now = datetime.datetime.now()
    time_now += datetime.timedelta(seconds=offset)
    return time_now.strftime("%Y-%m-%d %H:%M:%S")


def puny_to_utf8(name, strict_idna_2008=None):
    if strict_idna_2008 is None:
        strict_idna_2008 = policy.policy("strict_idna2008")
    try:
        idn = idna.decode(name)
        return idn
    except idna.IDNAError:
        if strict_idna_2008:
            return None
        try:
            idn = name.encode("utf-8").decode("idna")
            return idn
        except UnicodeError:
            return None
    return None
