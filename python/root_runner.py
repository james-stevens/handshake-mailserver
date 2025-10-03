#! /usr/bin/python3

import os
import time
import json
import subprocess
import argparse

import executor
import log


def user_create(data):
    if "name" not in data or "passwd" not in data:
        log.log("ERROR: 'name' or 'passwd' missing from 'user_create' data")
        return False
    try:
        subprocess.run(["/usr/local/bin/user_create", data["name"], data["passwd"]],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       check=True)
    except subprocess.CalledProcessError:
        return False
    return True


def user_password(data):
    if "name" not in data or "passwd" not in data:
        log.log("ERROR: 'name' or 'passwd' missing from 'user_password' data")
        return False
    try:
        subprocess.run(["/usr/local/bin/user_password", data["name"], data["passwd"]],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       check=True)
    except subprocess.CalledProcessError:
        return False
    return True


def test_test(data):
    log.log(f"TEST ROOT: {data}")
    return True


ROOT_CMDS = {"user_password": user_password, "user_create": user_create, "test": test_test}


def main(with_debug):
    log.init("ROOT backend", with_debug=with_debug)
    log.log("ROOT backend running")
    while True:
        if (file := executor.find_oldest_cmd("root")) is None:
            time.sleep(1)
        else:
            with open(file, "r") as fd:
                cmd_data = json.load(fd)
            os.remove(file)
            if "verb" not in cmd_data or "data" not in cmd_data:
                log.log("ERROR: 'verb' or 'data' missing from 'cmd_data' data")
            elif cmd_data["verb"] not in ROOT_CMDS:
                log.log(f"ERROR: Verb '{cmd_data['verb']}' is not supported")
            else:
                if not ROOT_CMDS[cmd_data["verb"]](cmd_data["data"]):
                    time.sleep(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ROOT Jobs Runner')
    parser.add_argument("-D", "--debug", default=False, help="Debug mode", action="store_true")
    args = parser.parse_args()
    main(args.debug)
