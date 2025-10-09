#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import json
import tempfile
import glob
import argparse


def create_command(pfx, cmd_type, cmd_data):
    dir = "/run/exec/" + cmd_type
    if not os.path.isdir(dir):
        return False
    with tempfile.NamedTemporaryFile("w+", dir=dir, encoding="utf-8", delete=False, prefix=pfx + "_") as fd:
        json.dump(cmd_data, fd)
        filename = fd.name
    fd.close()
    os.chmod(filename, 0o444)
    return True


def find_oldest_cmd(cmd_type):
    dir = "/run/exec/" + cmd_type
    if not os.path.isdir(dir):
        return False

    files = glob.glob(os.path.join(dir, '*'))
    files = [f for f in files if os.path.isfile(f) and oct(os.stat(f).st_mode)[-3:] == "444"]

    if not files:
        return None

    return min(files, key=os.path.getmtime)


def run_tests():
    print(create_command("test", "root", {"verb": "test", "data": {"value": "this is a test"}}))
    print("root ->", find_oldest_cmd("root"))
    print("norm ->", find_oldest_cmd("norm"))
    print(oct(os.stat(find_oldest_cmd("root")).st_mode))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ROOT Jobs Runner')
    parser.add_argument("-t", "--type", help="Command type (root/norm)")
    parser.add_argument("-d", "--data", help="Command data")
    parser.add_argument("-v", "--verb", help="Command verb")
    args = parser.parse_args()
    create_command("manual", args.type, {"verb": args.verb, "data": json.loads(args.data)})
