#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import time
import json
import argparse

import executor
import log


def install_passwd_files(data):
    for file in ["passwd", "shadow", "group"]:
        if os.path.isfile(f"/run/{file}.new"):
            os.rename(f"/run/{file}.new", f"/run/{file}")


def test_test(data):
    log.log(f"TEST ROOT: {data}")
    return True


ROOT_CMDS = {"install_passwd_files": install_passwd_files, "test": test_test}


def runner(with_debug):
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
    install_passwd_files(None)


def main():
    parser = argparse.ArgumentParser(description='ROOT Jobs Runner')
    parser.add_argument("-D", "--debug", default=False, help="Debug mode", action="store_true")
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    parser.add_argument("-O", "--one", help="Run one module")
    args = parser.parse_args()
    if args.one:
        if args.one not in ROOT_CMDS:
            log.log("ERROR: ROOT CMD '{args.one}' not valid")
            return
        ROOT_CMDS[args.one](None)

    elif args.test:
        run_tests()
    else:
        runner(args.debug)


if __name__ == "__main__":
    main()
