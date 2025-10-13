#! /usr/bin/python3

import os
import json
import time
import filelock
import subprocess
import argparse

import policy
import executor
import filecfg
import log

BASE_PASSWD = "/usr/local/etc/uid/passwd"
BASE_SHADOW = "/usr/local/etc/uid/shadow"
BASE_GROUP = "/usr/local/etc/uid/group"


def load_users():
    get_user_files = subprocess.run(["find", f"{policy.BASE}/service/users", "-type", "f", "-name", "*.json"],
                                    capture_output=True)
    users = {}
    for file in get_user_files.stdout.decode('utf-8').strip().split():
        lock = os.path.join(os.path.dirname(file), ".lock")
        user = file.split("/")[-1][:-5]
        with filelock.FileLock(lock), open(file, "r") as fd:
            users[user] = json.load(fd)
            users[user]["user"] = user
    return users


class UserData:
    def __init__(self):
        self.all_users = load_users()
        self.active_users = {
            user: self.all_users
            for user in self.all_users
            if user in self.all_users[user]["domains"] and self.all_users[user]["domains"][user]
        }
        self.taken_uids = {user["uid"]: user for user in self.active_users if "uid" in user}

        for user in self.active_users:
            if "uid" not in self.active_users[user]:
                this_uid = self.assign_uid()
                self.active_users[user]["uid"] = this_uid
                self.taken_uids[this_uid] = user
                filecfg.record_info_update("users", user, {"uid": this_uid})

    def new_unix_files(self, data):
        with open("/run/passwd.new", "w+") as fd:
            with open(BASE_PASSWD, "r") as old:
                lines = [line.strip() for line in old.readlines()]
            for user in self.active_users:
                this_user = self.active_users[user]
                lines.append(f"{user}:x:{this_user['uid']}:100::/opt/data/homedirs/{user}:/sbin/nologin")
            fd.write("\n".join(lines) + "\n")

        with open("/run/shadow.new", "w+") as fd:
            with open(BASE_SHADOW, "r") as old:
                lines = [line.strip() for line in old.readlines()]
            for user in self.active_users:
                this_user = self.active_users[user]
                lines.append(f"{user}:{this_user['password']}:20367:0:99999:7:::")
            fd.write("\n".join(lines) + "\n")

        with open("/run/group.new", "w+") as fd:
            with open(BASE_GROUP, "r") as old:
                lines = [line.strip() for line in old.readlines() if line[:6] != "users:"]
            lines.append("users:x:100:" + ",".join(list(self.active_users)))
            fd.write("\n".join(lines) + "\n")

    def assign_uid(self):
        for x in range(1000, 100000):
            if x not in self.taken_uids:
                return x


def test_test(data):
    log.log(f"TEST DOMS: {data}")
    return True


Users = UserData()

DOMS_CMDS = {"new_unix_files": Users.new_unix_files, "test": test_test}


def runner(with_debug):
    log.init("DOMS backend", with_debug=with_debug)
    log.log("DOMS backend running")
    while True:
        if (file := executor.find_oldest_cmd("doms")) is None:
            time.sleep(1)
        else:
            with open(file, "r") as fd:
                cmd_data = json.load(fd)
            os.remove(file)
            if "verb" not in cmd_data or "data" not in cmd_data:
                log.log("ERROR: 'verb' or 'data' missing from 'cmd_data' data")
            elif cmd_data["verb"] not in DOMS_CMDS:
                log.log(f"ERROR: Verb '{cmd_data['verb']}' is not supported")
            else:
                if not DOMS_CMDS[cmd_data["verb"]](cmd_data["data"]):
                    time.sleep(5)


def run_tests():
    load_users()


def main():
    parser = argparse.ArgumentParser(description='DOMS Jobs Runner')
    parser.add_argument("-D", "--debug", default=False, help="Debug mode", action="store_true")
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    parser.add_argument("-O", "--one", help="Run one module")
    args = parser.parse_args()
    if args.one:
        if args.one not in DOMS_CMDS:
            log.log("ERROR: DOMS CMD '{args.one}' not valid")
            return
        DOMS_CMDS[args.one](None)

    elif args.test:
        run_tests()

    else:
        runner(args.debug)


if __name__ == "__main__":
    main()
