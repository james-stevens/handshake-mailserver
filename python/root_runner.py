#! /usr/bin/python3

import os
import time
import json
import subprocess
import argparse

import executor
import filecfg
import log


def user_create(user):
    this_user = filecfg.record_info_load("users", user, True)
    if "user" not in this_user or "password" not in this_user:
        log.log("ERROR: 'name' or 'password' missing from 'user_password' data")
        return False

    try:
        subprocess.run(["adduser","-G","users","-h","/opt/data/homedirs/"+user,"-s","/sbin/nologin","-D",user],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       check=True)
    except subprocess.CalledProcessError:
        return False

    return True


def user_password(user):
    this_user = filecfg.record_info_load("users", user, True)
    if "user" not in this_user or "password" not in this_user:
        log.log("ERROR: 'name' or 'password' missing from 'user_password' data")
        return False

    with open("/etc/shadow", "r") as fd:
        lines = [line.strip().split(":") for line in fd.readlines()]

    by_name = {line[0]: line for line in lines}

    if user in by_name:
        by_name[user][1] = this_user["password"]
    else:
        lines.append([user, this_user["password"], '20364', '0', '99999', '7', '', '', ''])

    with open("/etc/shadow", "w") as fd:
        fd.write('\n'.join([":".join(line) for line in lines]) + "\n")

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


def run_tests():
    user_password("earl.webmail")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ROOT Jobs Runner')
    parser.add_argument("-D", "--debug", default=False, help="Debug mode", action="store_true")
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    args = parser.parse_args()
    if args.test:
        run_tests()
    else:
        main(args.debug)
