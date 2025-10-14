#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import time
import json
import argparse

import executor
import log
from policy import this_policy as policy


def get_gid(grp):
    with open("/usr/local/etc/uid/group", "r") as fd:
        for line in fd.readlines():
            parts = line.strip().split(":")
            if parts[0] == grp:
                return int(parts[2])
    return None


PASSWD_FILE_PERMS = {
    "passwd": [0, 0, 0o644],
    "group": [0, 0, 0o644],
    "shadow": [0, get_gid("shadow"), 0o640],
}


def make_home_dir(data):
    if "user" not in data or "uid" not in data:
        return False
    path = os.path.join(policy.BASE, "homedirs", data["user"])
    os.mkdir(path)
    os.chown(path, data["uid"], get_gid("users"))
    return True


def install_passwd_files(data):
    for file in ["passwd", "shadow", "group"]:
        src = f"/run/{file}.new"
        if os.path.isfile(src):
            uid, gid, perm = PASSWD_FILE_PERMS[file]
            os.chmod(src, perm)
            os.chown(src, uid, gid)
            os.rename(src, f"/run/{file}")
    executor.create_command("install_passwd_files", "doms", {"verb": "email_users_welcome"})
    return True


def test_test(data):
    log.log(f"TEST ROOT: {data}")
    return True


ROOT_CMDS = {"make_home_dir": make_home_dir, "install_passwd_files": install_passwd_files, "test": test_test}


def runner(with_debug, with_logging):
    log.init("ROOT backend", with_debug=with_debug, with_logging=with_logging)
    log.log("ROOT backend running")
    while True:
        if (file := executor.find_oldest_cmd("root")) is None:
            time.sleep(1)
        else:
            with open(file, "r") as fd:
                cmd_data = json.load(fd)
            os.remove(file)
            if "verb" not in cmd_data:
                log.log(f"ERROR: 'verb' missing from '{cmd_data}' data")
            elif cmd_data["verb"] not in ROOT_CMDS:
                log.log(f"ERROR: Verb '{cmd_data['verb']}' is not supported")
            else:
                log.debug(f"Running cmd: '{cmd_data['verb']}'")
                if not ROOT_CMDS[cmd_data["verb"]](cmd_data.get("data", None)):
                    log.log(f"ERROR: cmd '{cmd_data['verb']}' failed")
                    time.sleep(5)


def run_tests():
    install_passwd_files(None)
    print(PASSWD_FILE_PERMS)
    print(get_gid("shadow"))


def main():
    parser = argparse.ArgumentParser(description='ROOT Jobs Runner')
    parser.add_argument("-D", "--debug", default=False, help="Debug mode", action="store_true")
    parser.add_argument("-S", "--syslog", default=False, help="Log to syslog", action="store_true")
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    parser.add_argument("-O", "--one", help="Run one module")
    parser.add_argument("-d", "--data", help="data for running one")
    args = parser.parse_args()
    if args.one:
        log.init("ROOT run one", with_debug=True, with_logging=args.syslog)
        if args.one not in ROOT_CMDS:
            log.log("ERROR: ROOT CMD '{args.one}' not valid")
            return
        ROOT_CMDS[args.one](json.loads(args.data) if args.data else None)

    elif args.test:
        log.init("ROOT run test", with_debug=True, with_logging=args.syslog)
        run_tests()
    else:
        runner(args.debug, args.syslog)


if __name__ == "__main__":
    main()
