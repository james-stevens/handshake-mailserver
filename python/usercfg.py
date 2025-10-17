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
    path = os.path.join(policy.BASE, "service", "users", this_hash[0], this_hash[1])
    return os.path.join(path, user + ".json"), os.path.join(path, ".lock")


def return_user(js, user):
    if user not in js:
        return None
    ret_user = js[user]
    ret_user["user"] = user
    return ret_user


def user_info_load(user):
    user_file, __ = user_file_name(user)
    if not os.path.isfile(user_file):
        return None, "File not found"

    with open(user_file, "r") as fd:
        js = json.load(fd)

    js["user"] = user
    return True, js


def user_info_update(user, data):
    user_file, lock_file = user_file_name(user)
    if not os.path.isfile(user_file):
        return None

    if data is None and os.path.isfile(user_file):
        os.remove(user_file)
        return True, None

    with filelock.FileLock(lock_file):

        with open(user_file, "r") as fd:
            js = json.load(fd)

            for item in data:
                if data[item] is None:
                    if item in js:
                        del js[item]
                else:
                    js[item] = data[item]

        js["amended_dt"] = misc.now()
        new_file = user_file + ".new"
        with open(new_file, "w") as fd:
            json.dump(js, fd, indent=2)
        os.replace(new_file, user_file)

        js["user"] = user
        return True, js


if __name__ == "__main__":
    print("INFO LOAD ->", user_info_load("users", "anon.webmail"))
    print("INFO ADD ->", user_info_update("users", "anon.webmail", {"temp": "value"}))
    print("INFO LOAD ->", user_info_load("users", "anon.webmail"))
    print("INFO ADD ->", user_info_update("users", "anon.webmail", {"temp": None}))
    print("INFO LOAD ->", user_info_load("users", "anon.webmail"))
    print("INFO LOAD ->", user_info_load("users", "anon.webmail"))
