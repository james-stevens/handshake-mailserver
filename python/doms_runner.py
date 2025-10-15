#! /usr/bin/python3

import os
import json
import time
import filelock
import subprocess
import argparse
import base64
import validators

from policy import this_policy as policy
import executor
import filecfg
import resolv
import validation
import log
import misc

BASE_UX_DIR = "/usr/local/etc/uid"


def get_user_from_emails(emails):
    default_mail_domain = policy.get("default_mail_domain")
    ret_user = None
    new_list = []
    for email in emails:
        user, dom = email
        new_list.append([user, dom.lower()])
        if dom == default_mail_domain:
            ret_user = user
    return ret_user, new_list


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

        self.need_remake_system_files = False
        self.need_remake_mail_files = False
        for user in self.active_users:
            this_user = self.all_users[user]
            if "uid" not in this_user:
                self.assign_uid(this_user)
        self.run_mx_check()
        self.check_remake_system_files()
        self.check_remake_mail_files()

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
        self.need_remake_system_files = True

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
        log.debug("User age check")
        # CODE - flush away users that didn't activate
        pass

    def run_mx_check(self, data):
        self.need_remake_mail_files = self.need_remake_system_files = False
        for user in self.all_users:
            self.check_one_user(self.all_users[user])
        self.check_remake_system_files()
        return True

    def new_mail_files(self):
        # CODE - write new postfix files
        pass

    def check_remake_mail_files(self):
        log.debug(f"need_remake_mail_files: {self.need_remake_mail_files}")
        if not self.need_remake_mail_files:
            return
        self.need_remake_mail_files = False
        self.new_mail_files(None)
        executor.create_command("doms_runner_user_update", "root", {"verb": "install_mail_files"})

    def check_remake_system_files(self):
        log.debug(f"need_remake_system_files: {self.need_remake_system_files}")
        if not self.need_remake_system_files:
            return
        self.need_remake_system_files = False
        self.new_unix_files(None)
        executor.create_command("doms_runner_user_update", "root", {"verb": "install_passwd_files"})

    def check_one_user(self, this_user):
        save_this_user = False
        doms = this_user.get("domains", None)
        if doms is not None:
            for dom in [d for d in doms if not doms[d]]:
                if self.check_one_domain(this_user, dom):
                    save_this_user = True
                    self.need_remake_mail_files = True

        if save_this_user:
            log.debug(f"saving user '{this_user['user']}'")
            filecfg.record_info_update("users", this_user["user"], {
                "domains": this_user["domains"],
                "events": this_user["events"]
            })

    def check_one_domain(self, this_user, domain):
        if not validation.check_mx_match(this_user, self.resolver.resolv(domain, "mx")):
            log.debug(f"check_one_domain FAIL: {this_user['user']} {domain}")
            return False

        if this_user["user"] == domain:
            self.assign_uid(this_user)

        this_user["domains"][domain] = True
        this_user["events"].append({"when_dt": misc.now(), "desc": "Domain '{domain}' is now active"})

        # CODE - email user a new domain is now active, if secondary domain!
        log.debug(f"check_one_domain PASS: {this_user['user']}, {domain}")
        return True

    def email_users_welcome(self, data):
        for user in self.users_to_email:
            log.debug(f"Email welcome to '{user}'")
        self.users_to_email = []
        # CODE - send out welcome email
        return True

    def identity_changed(self, data):
        emails = [
            item["Email"].rstrip(".").split("@")
            for item in json.loads(base64.b64decode(data.get("data", "{}")).decode("utf-8"))
            if validators.email(item["Email"])
        ]
        user, emails = get_user_from_emails(emails)
        log.debug(f"USER:{user}, EMAILS:{emails}")
        if user is None:
            log.log(f"ERROR: Unbable to identify user in {emails}")
            return False
        if user not in self.all_users:
            log.log(f"ERROR: user '{user}' does not seem to exist")
            return False

        this_user = self.all_users[user]

        this_user["identities"] = [user + "@" + dom for user, dom in emails]
        email_doms = [dom for __, dom in emails]

        for dom in list(this_user["domains"]):
            if dom not in email_doms:
                del this_user["domains"][dom]

        default_mail_domain = policy.get("default_mail_domain")
        for dom in email_doms:
            if dom not in this_user["domains"] and dom != default_mail_domain:
                this_user["domains"][dom] = False

        this_user["identities"].sort()
        this_user["events"].append({"when_dt": misc.now(), "desc": "Email Identities updated"})
        filecfg.record_info_update("users", this_user["user"], {
            "events": this_user["events"],
            "identities": this_user["identities"],
            "domains": this_user["domains"]
        })

        self.check_one_user(this_user)
        return True

    def new_user_added(self, data):
        if (user := data.get("user", None)) is None:
            return False
        if (this_user := filecfg.record_info_load("users", user)) is None:
            return False
        this_user["user"] = user
        self.all_users[user] = this_user
        return True


def test_test(data):
    log.log(f"TEST DOMS: {data}")
    return True


Users = UserData()

DOMS_CMDS = {
    "new_user_added": Users.new_user_added,
    "identity_changed": Users.identity_changed,
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
    parser.add_argument("-d", "--data", help="data for running one")
    args = parser.parse_args()

    Users.startup()
    Users.run_mx_check(None)

    if args.one:
        log.init("DOMS run one", with_debug=True, with_logging=args.syslog)
        if args.one not in DOMS_CMDS:
            log.log("ERROR: DOMS CMD '{args.one}' not valid")
            return
        DOMS_CMDS[args.one](json.loads(args.data) if args.data else None)

    elif args.test:
        log.init("DOMS run test", with_debug=True, with_logging=args.syslog)
        run_tests()

    else:
        runner(args.debug, args.syslog)


if __name__ == "__main__":
    main()
