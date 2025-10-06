#! /usr/bin/python3

import os
import filelock
import json

import policy

CFG_DIR = policy.BASE + "/service/"
LCK_DIR = "/run/"


def return_record(file, js, record, for_login):
    print(">>>>>>",record)
    print(">>>>>>",js)
    if record not in js:
        return None

    ret_record = js[record]
    ret_record[file.rstrip("s")] = record

    if not for_login:
        del ret_record["password"]
    return ret_record


def record_info_load(file, record, for_login=False):
    record_file = CFG_DIR + file + ".json"
    lock_file = LCK_DIR + file + ".lock"
    if not os.path.isfile(record_file):
        return None
    with filelock.FileLock(lock_file), open(record_file, "r") as fd:
        js = json.load(fd)

    return return_record(file, js, record, for_login)


def record_info_update(file, record, data):
    record_file = CFG_DIR + file + ".json"
    if not os.path.isfile(record_file):
        return None
    lock_file = LCK_DIR + file + ".lock"

    with filelock.FileLock(lock_file):

        with open(record_file, "r") as fd:
            js = json.load(fd)

        if record not in js:
            return None

        if data is None:
            del js[record]
        else:
            for item in data:
                if data[item] is None:
                    del js[record][item]
                else:
                    js[record][item] = data[item]

        with open(record_file, "w") as fd:
            json.dump(js, fd)

        return return_record(file, js, record, False)


if __name__ == "__main__":
    print("INFO LOAD ->", record_info_load("users", "lord.webmail"))
    print("INFO ADD ->", record_info_update("users", "lord.webmail", {"temp": "value"}))
    print("INFO LOAD ->", record_info_load("users", "lord.webmail"))
    print("INFO ADD ->", record_info_update("users", "lord.webmail", {"temp": None}))
    print("INFO LOAD ->", record_info_load("users", "lord.webmail"))
    print("INFO LOAD ->", record_info_load("users", "lord.webmail",for_login=True))
