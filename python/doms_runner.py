#! /usr/bin/python3

import os
import json
import time
import filelock
import subprocess
import argparse

from policy import this_policy as policy
import executor
import filecfg
import resolv
import log

BASE_UX_DIR = "/usr/local/etc/uid"


def check_mx_match(user, mx_rrs):
    if ((mx_rrs is None) or (mx_rrs.get("Status", 99) != 0) or ("Answer" not in mx_rrs)
            or (not isinstance(mx_rrs["Answer"], list)) or (len(mx_rrs["Answer"]) != 1)):
        return False
    mx = mx_rrs["Answer"][0]
    if mx.get("type", 0) != 15 or mx.get("data", None) is None:
        return False
    mx_rr = mx["data"].rstrip(".").lower().split()[1]
    chk_rr = (user["mx"] + "." + policy.get("default_mail_domain")).rstrip(".").lower()
    return chk_rr == mx_rr


class UserData:
    def __init__(self):
        self.users_to_email = []

    def startup(self):
        self.load_user_details()
        self.resolver = resolv.Resolver()

    def load_user_details(self):
        self.load_users()
        self.active_users = {
            user: True
            for user in self.all_users
            if user in self.all_users[user]["domains"] and self.all_users[user]["domains"][user]
        }
        self.taken_uids = {user["uid"]: user for user in self.active_users if "uid" in user}

        for user in self.active_users:
            this_user = self.all_users[user]
            if "uid" not in this_user:
                self.assign_uid(this_user)

    def assign_uid(self, this_user):
        if "uid" in this_user:
            return
        user = this_user["user"]
        this_uid = self.find_free_uid()
        this_user["uid"] = this_uid
        self.taken_uids[this_uid] = user
        self.active_users[user] = True
        filecfg.record_info_update("users", user, {"uid": this_uid})
        executor.create_command("doms_runner_user_add", "root", {
            "verb": "make_home_dir",
            "data": {
                "uid": this_uid,
                "user": user
            }
        })
        self.users_to_email.append(user)

    def load_users(self):
        get_user_files = subprocess.run(
            ["find", os.path.join(policy.BASE, "service", "users"), "-type", "f", "-name", "*.json"],
            capture_output=True)
        self.all_users = {}
        for file in get_user_files.stdout.decode('utf-8').strip().split():
            lock = os.path.join(os.path.dirname(file), ".lock")
            user = file.split("/")[-1][:-5]
            with filelock.FileLock(lock), open(file, "r") as fd:
                self.all_users[user] = json.load(fd)
            self.all_users[user]["user"] = user
            self.all_users[user]["file"] = file

    def new_unix_files(self, data):
        base_data = {}
        for file in ["passwd", "shadow", "group"]:
            with open(os.path.join(BASE_UX_DIR, file), "r") as fd:
                base_data[file] = [line.strip() for line in fd.readlines()]

        with open("/run/passwd.new", "w+") as fd:
            lines = base_data["passwd"]
            for user in self.active_users:
                this_user = self.all_users[user]
                lines.append(f"{user}:x:{this_user['uid']}:100::/opt/data/homedirs/{user}:/sbin/nologin")
            fd.write("\n".join(lines) + "\n")

        with open("/run/shadow.new", "w+") as fd:
            lines = base_data["shadow"]
            for user in self.active_users:
                this_user = self.all_users[user]
                lines.append(f"{user}:{this_user['password']}:20367:0:99999:7:::")
            fd.write("\n".join(lines) + "\n")

        with open("/run/group.new", "w+") as fd:
            lines = [line for line in base_data["group"] if line[:6] != "users:"]
            lines.append("users:x:100:" + ",".join(list(self.active_users)))
            fd.write("\n".join(lines) + "\n")

    def find_free_uid(self):
        for x in range(1000, 30000):
            if x not in self.taken_uids:
                return x

    def user_age_check(self, data):
        pass

    def run_mx_check(self, data):
        need_remake_system_files = False
        for user in self.all_users:
            this_user = self.all_users[user]
            save_this_user = False
            doms = this_user.get("domains", None)
            if doms is not None:
                for dom in [d for d in doms if not doms[d]]:
                    ret = self.check_one_domain(this_user, dom)
                    need_remake_system_files = need_remake_system_files or ret
                    save_this_user = save_this_user or ret
            if save_this_user:
                log.debug(f"saving user '{this_user['user']}'")
                filecfg.record_info_update("users", this_user["user"], {
                    "identities": this_user["identities"],
                    "domains": this_user["domains"]
                })
        log.debug(f"need_remake_system_files: {need_remake_system_files}")
        if need_remake_system_files:
            self.new_unix_files(None)
            executor.create_command("doms_runner_user_update", "root", {"verb": "install_passwd_files"})
        return True

    def check_one_domain(self, this_user, domain):
        if not check_mx_match(this_user, self.resolver.resolv(domain, "mx")):
            log.debug(f"check_one_domain FAIL: {this_user['user']} {domain}")
            return False

        if this_user["user"] == domain:
            self.assign_uid(this_user)

        this_user["domains"][domain] = True
        for email in this_user["identities"]:
            if not this_user["identities"][email]:
                split_email = email.rstrip(".").lower().split("@")
                if split_email[1] == domain or (split_email[1] == policy.get("default_mail_domain")
                                                and split_email[0] == domain):
                    this_user["identities"][email] = True
        log.debug(f"check_one_domain PASS: {this_user['user']}, {domain}")
        return True

    def email_users_welcome(self, data):
        for user in self.users_to_email:
            log.debug(f"Email welcome to '{user}'")
        self.users_to_email = []
        # CODE - send out email
        return True


def test_test(data):
    log.log(f"TEST DOMS: {data}")
    return True


Users = UserData()

DOMS_CMDS = {
    "email_users_welcome": Users.email_users_welcome,
    "user_age_check": Users.user_age_check,
    "run_mx_check": Users.run_mx_check,
    "new_unix_files": Users.new_unix_files,
    "test": test_test
}


def runner(with_debug, with_logging):
    log.init("DOMS backend", with_debug=with_debug, with_logging=with_logging)
    log.log("DOMS backend running")
    while True:
        if (file := executor.find_oldest_cmd("doms")) is None:
            time.sleep(1)
        else:
            with open(file, "r") as fd:
                cmd_data = json.load(fd)
            os.remove(file)
            if "verb" not in cmd_data:
                log.log(f"ERROR: 'verb' missing from '{cmd_data}' data")
            elif cmd_data["verb"] not in DOMS_CMDS:
                log.log(f"ERROR: Verb '{cmd_data['verb']}' is not supported")
            else:
                if not DOMS_CMDS[cmd_data["verb"]](cmd_data.get("data", None)):
                    log.log(f"ERROR: cmd '{cmd_data['verb']}' failed")
                    time.sleep(5)


def run_tests():
    print(json.dumps(Users.all_users, indent=2))


def main():
    parser = argparse.ArgumentParser(description='DOMS Jobs Runner')
    parser.add_argument("-D", "--debug", default=False, help="Debug mode", action="store_true")
    parser.add_argument("-S", "--syslog", default=False, help="With syslog", action="store_true")
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    parser.add_argument("-O", "--one", help="Run one module")
    args = parser.parse_args()

    Users.startup()
    Users.run_mx_check(None)

    if args.one:
        log.init("DOMS run one", with_debug=True, with_logging=args.syslog)
        if args.one not in DOMS_CMDS:
            log.log("ERROR: DOMS CMD '{args.one}' not valid")
            return
        DOMS_CMDS[args.one](None)

    elif args.test:
        log.init("DOMS run test", with_debug=True, with_logging=args.syslog)
        run_tests()

    else:
        runner(args.debug, args.syslog)


if __name__ == "__main__":
    main()
