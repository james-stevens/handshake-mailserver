#! /usr/bin/python3
# (c) Copyright 2019-2020, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import re
import sys
# import json

import misc
import resolv
import filecfg
# import log
from policy import this_policy as policy

IS_HOST = r'^(\*\.|)([\_a-z0-9]([-a-z-0-9]{0,61}[a-z0-9]){0,1}\.)+[a-z0-9]([-a-z0-9]{0,61}[a-z0-9]){0,1}[.]?$'
IS_FQDN = r'^([a-z0-9]([-a-z-0-9]{0,61}[a-z0-9]){0,1}\.)+[a-z0-9]([-a-z0-9]{0,61}[a-z0-9]){0,1}[.]?$'
IS_TLD = r'^[a-z0-9]([-a-z-0-9]{0,61}[a-z0-9]){0,1}[.]?$'

with open("/usr/local/etc/icann_tlds", "r") as fd:
    icann_tlds = {line.strip(): True for line in fd.readlines()}


def has_idn(name):
    if name is None or len(name) < 5:
        return False
    if name[:4] == 'xn--':
        return True
    return name.find(".xn--") > 0


def is_valid_handshake(name):
    return is_valid_fqdn(name) or is_valid_tld(name)


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
    if not has_idn(name):
        return True
    return misc.puny_to_utf8(name, strict_idna_2008)


def is_valid_host(name):
    if name is None or not isinstance(name, str):
        return False
    if len(name) > 255 or len(name) <= 0:
        return False
    return re.match(IS_HOST, name, re.IGNORECASE) is not None


def normalise_user(sent_data):
    sent_data["user"] = sent_data["user"].strip(".").lower()


NORMALISE_DATA = {"user": normalise_user}


def web_validate(sent_data, rules):
    for rname, rule in rules.items():
        if len(rule) != 2:
            return False, "Invalid rule data"
        required, valid_func = rule

        have_item = rname in sent_data
        if required and not have_item:
            return False, f"Insufficient data - {rname}"

        if rname in NORMALISE_DATA:
            NORMALISE_DATA[rname](sent_data)

        if have_item and valid_func is not None:
            ret = valid_func(sent_data.get(rname, None))
            if isinstance(ret, tuple):
                ok, reply = ret
            elif isinstance(ret, bool):
                ok = ret
                reply = f"Invalid data for {rname}"
            else:
                return False, f"Invalid response from validator for '{rname}'"
            if not ok:
                return ok, reply

    for item in sent_data:
        if item not in rules:
            return False, "Extra data sent"

    return True, None


def pre_check_user(user, is_new):
    if not is_valid_handshake(user):
        return False, "Invalid account name"

    tld = user.split(".")[-1]
    if tld in icann_tlds and not policy.get("allow_icann_domains"):
        return False, "ICANN domains are not allowed"

    file, __ = filecfg.user_file_name(user, True)
    has_file = os.path.isfile(file)

    if is_new and has_file:
        return False, "Domain is already registered"

    if (not is_new) and (not has_file):
        return False, "Invalid login"

    return True, tld


def web_valid_reg_account(user):
    ok, reply = pre_check_user(user, False)
    return ok, reply


def web_valid_new_account(user):
    ok, reply = pre_check_user(user, True)
    if not ok:
        return ok, reply

    tld = reply
    res = resolv.Resolver()
    tld_dns = res.resolv(tld, "px", flags=0)

    if tld_dns.get("Status", 3) != 0:
        return False, "TLD does not exist"

    if tld == user:
        return True, None

    user_dns = res.resolv(user, "px")
    if user_dns.get("Status", 3) != 0:
        return False, "Domain does not exist"

    return True, None


# for testing
if __name__ == "__main__":
    x = {"user": sys.argv[1]}
    print("OK NEW:", web_validate(x, {"user": [True, web_valid_new_account]}))
    print("OK REG:", web_validate(x, {"user": [True, web_valid_reg_account]}))
    print("OK HOST:", web_validate({"host": "xxx.yyy"}, {"host": [True, is_valid_fqdn]}))
    print("OK HOST:", web_validate({"host": "1 2"}, {"host": [True, is_valid_fqdn]}))
    print(x)


def not_now():
    for host in ["A_A", "A_A.xxxx.cccc", "www.gstatic.com.", "m.files.bbci.co.uk."]:
        print("is_valid_host", host, is_valid_host(host))
        print("is_valid_fqdn", host, is_valid_fqdn(host))
    print(
        web_validate({
            "idn": "xn--fred",
            "host": "www.gstatic.com",
            "junk": "some junk"
        }, {
            "idn": [True, has_idn],
            "idn2": [False, has_idn],
            "host": [True, is_valid_fqdn]
        }))
