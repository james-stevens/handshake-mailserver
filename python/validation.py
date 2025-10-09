#! /usr/bin/python3
# (c) Copyright 2019-2020, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import re

import misc

IS_HOST = r'^(\*\.|)([\_a-z0-9]([-a-z-0-9]{0,61}[a-z0-9]){0,1}\.)+[a-z0-9]([-a-z0-9]{0,61}[a-z0-9]){0,1}[.]?$'
IS_FQDN = r'^([a-z0-9]([-a-z-0-9]{0,61}[a-z0-9]){0,1}\.)+[a-z0-9]([-a-z0-9]{0,61}[a-z0-9]){0,1}[.]?$'
IS_TLD = r'^[a-z0-9]([-a-z-0-9]{0,61}[a-z0-9]){0,1}[.]?$'


def has_idn(name):
    if name[:4] == 'xn--':
        return True
    return name.find(".xn--") > 0


def is_valid_tld(name):
    if name is None or not isinstance(name, str):
        return False
    if len(name) > 63 or len(name) <= 0:
        return False

    return re.match(IS_TLD, name, re.IGNORECASE) is not None


def is_valid_fqdn(name, strict_idna_2008=None):
    if name is None or not isinstance(name, str):
        return False
    if len(name) > 255 or len(name) <= 0:
        return False
    if re.match(IS_FQDN, name, re.IGNORECASE) is None:
        return False
    return not (has_idn(name) and misc.puny_to_utf8(name, strict_idna_2008) is None)


def is_valid_host(name):
    if name is None or not isinstance(name, str):
        return False
    if len(name) > 255 or len(name) <= 0:
        return False
    return re.match(IS_HOST, name, re.IGNORECASE) is not None


# for testing
if __name__ == "__main__":
    for host in ["A_A", "A_A.xxxx.cccc", "www.gstatic.com.", "m.files.bbci.co.uk."]:
        print("is_valid_host", host, is_valid_host(host))
        print("is_valid_fqdn", host, is_valid_fqdn(host))
