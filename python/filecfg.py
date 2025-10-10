#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import filelock
import json

import misc
from policy import this_policy as policy

CFG_DIR = os.path.join(policy.BASE, "/service/")
LCK_DIR = "/run/"


def calc_hash(user):
    hashval = 2166136261
    for ch in user:
        hashval = hashval * 16777619
        hashval = hashval ^ ord(ch)
    ret = hex(hashval & 0xffff).upper()[2:]
    return [ret[:2], ret[2:]]


def user_file_name(user, with_make_dir=False):
    this_hash = calc_hash(user)
    if with_make_dir:
        d = policy.BASE
        for dir in ["service", "users", this_hash[0], this_hash[1]]:
            d = os.path.join(d, dir)
            if not os.path.isdir(d):
                os.mkdir(d, mode=0o755)
    return os.path.join(policy.BASE, "service", "users", this_hash[0], this_hash[1], user + ".json")


def get_file_name(file, record):
    if file == "users":
        return user_file_name(record)
    else:
        return os.path.join(CFG_DIR, file + ".json")


def return_record(file, js, record):
    if record not in js:
        return None
    ret_record = js[record]
    ret_record[file.rstrip("s")] = record
    return ret_record


def record_info_load(file, record):
    record_file = get_file_name(file, record)
    lock_file = os.path.join(LCK_DIR, file + ".lock")
    if not os.path.isfile(record_file):
        return None, "File not found"

    with filelock.FileLock(lock_file), open(record_file, "r") as fd:
        js = json.load(fd)

    js[file.rstrip("s")] = record
    return True, js


def record_info_update(file, record, data):
    record_file = get_file_name(file, record)
    if not os.path.isfile(record_file):
        return None
    lock_file = os.path.join(LCK_DIR, file + ".lock")

    if data is None and os.path.isfile(record_file):
        os.remove(record_file)
        return True, None

    with filelock.FileLock(lock_file):

        with open(record_file, "r") as fd:
            js = json.load(fd)

            for item in data:
                if data[item] is None:
                    if item in js:
                        del js[item]
                else:
                    js[item] = data[item]

        js["amended_dt"] = misc.now()
        with open(record_file, "w") as fd:
            json.dump(js, fd, indent=2)

        js[file.rstrip("s")] = record
        return True, js


if __name__ == "__main__":
    print("INFO LOAD ->", record_info_load("users", "lord.webmail"))
    print("INFO ADD ->", record_info_update("users", "lord.webmail", {"temp": "value"}))
    print("INFO LOAD ->", record_info_load("users", "lord.webmail"))
    print("INFO ADD ->", record_info_update("users", "lord.webmail", {"temp": None}))
    print("INFO LOAD ->", record_info_load("users", "lord.webmail"))
    print("INFO LOAD ->", record_info_load("users", "lord.webmail"))
