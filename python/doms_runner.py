#! /usr/bin/python3

import os
import json
import time
import filelock
import subprocess
import argparse
import base64

from policy import this_policy as policy
import executor
import filecfg
import resolv
import validation
import log
import misc

BASE_UX_DIR = "/usr/local/etc/uid"


def user_to_json(user_data):
    return json.dumps({"domains": user_data["domains"], "identities": user_data["identities"]})


def user_has_changed(old_user, this_user):
    return user_to_json(old_user) != user_to_json(this_user)


def clean_up_emails(emails):
    default_mail_domain = policy.get("default_mail_domain").rstrip(".").lower()
    new_list = []
    for email in [e for e in emails if validation.is_valid_email(e)]:
        user, dom = email.split("@")
        if dom != default_mail_domain:
            new_list.append([user, dom.rstrip(".").lower()])
    return new_list


class UserData:
    def __init__(self):
        self.users_to_welcome = []
        self.need_remake_mail_files = False
        self.need_remake_system_files = False
        self.resolver = None
        self.active_users = None
        self.taken_uids = None
        self.active_users = None

    def startup(self):
        self.resolver = resolv.Resolver()
        self.load_user_details()

    def load_user_details(self):
        self.load_users()
        self.active_users = [user for user in self.all_users if validation.is_user_active(self.all_users[user])]
        self.taken_uids = {
            self.all_users[user]["uid"]: True
            for user in self.active_users if self.all_users[user].get("uid", 0) > 100
        }

        for user in self.active_users:
            this_user = self.all_users[user]
            if "uid" not in this_user:
                self.assign_uid(this_user)

        self.run_mx_check(None)
        self.check_remake_files()

    def assign_uid(self, this_user):
        if "uid" in this_user:
            return
        user = this_user["user"]
        this_uid = self.find_free_uid()
        this_user["uid"] = this_uid
        self.taken_uids[this_uid] = True
        self.active_users.append(user)
        filecfg.record_info_update("users", user, {"uid": this_uid})
        executor.create_command("doms_runner_user_add", "root", {
            "verb": "make_home_dir",
            "data": {
                "uid": this_uid,
                "user": user
            }
        })
        self.users_to_welcome.append(user)
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

    def remake_unix_files(self, data):
        base_data = {}
        for file in ["passwd", "shadow", "group"]:
            with open(os.path.join(BASE_UX_DIR, file), "r") as fd:
                base_data[file] = [line.strip() for line in fd.readlines()]

        with open("/run/passwd.tmp", "w+") as fd:
            lines = base_data["passwd"]
            for user in self.active_users:
                this_user = self.all_users[user]
                lines.append(f"{user}:x:{this_user['uid']}:100::/opt/data/homedirs/{user}:/sbin/nologin")
            fd.write("\n".join(lines) + "\n")

        with open("/run/shadow.tmp", "w+") as fd:
            lines = base_data["shadow"]
            for user in self.active_users:
                this_user = self.all_users[user]
                lines.append(f"{user}:{this_user['password']}:20367:0:99999:7:::")
            fd.write("\n".join(lines) + "\n")

        with open("/run/group.tmp", "w+") as fd:
            lines = [line for line in base_data["group"] if line[:6] != "users:"]
            lines.append("users:x:100:" + ",".join(self.active_users))
            fd.write("\n".join(lines) + "\n")

        for file in ["passwd", "shadow", "group"]:
            os.replace(f"/run/{file}.tmp", f"/run/{file}.new")

    def find_free_uid(self):
        for x in range(1000, 30000):
            if x not in self.taken_uids:
                return x
        return None

    def user_age_check(self, data):
        log.debug("User age check")
        # CODE - flush away users that didn't activate
        pass

    def run_mx_check(self, data=None):
        if data is not None:
            self.check_one_user(data)
        else:
            for user in self.all_users:
                self.check_one_user(self.all_users[user])
        return True

    def remake_mail_files(self, data):
        default_mail_domain = policy.get("default_mail_domain").rstrip(".").lower()

        pfx = os.path.join(policy.BASE, "postfix", "data", "transport")
        with open(pfx + ".tmp", "w") as fd:
            fd.write(f"{default_mail_domain} local: $myhostname\n")
            for user in self.active_users:
                doms = self.all_users[user]["domains"]
                for dom in [d for d in doms if doms[d]]:
                    fd.write(f"{dom} local: $myhostname\n")

        pfx = os.path.join(policy.BASE, "postfix", "data", "virtual")
        with open(pfx + ".tmp", "w") as fd:
            fd.write(f"manager@{default_mail_domain} manager\n")
            fd.write(f"root@{default_mail_domain} manager\n")
            fd.write(f"postmaster@{default_mail_domain} manager\n")
            fd.write(f"postfix@{default_mail_domain} manager\n")
            for user in self.active_users:
                user_data = self.all_users[user]
                fd.write(f"{user}@{default_mail_domain} {user}\n")
                for email in [e for e in user_data["identities"] if validation.is_email_active(user_data, e)]:
                    fd.write(f"{email} {user}\n")

        for file in ["transport", "virtual"]:
            pfx = os.path.join(policy.BASE, "postfix", "data", file)
            os.replace(pfx + ".tmp", pfx + ".new")

    def check_remake_files(self):
        log.debug(
            f"need_remake_mail_files: {self.need_remake_mail_files}, need_remake_system_files: {self.need_remake_system_files}"
        )
        if self.need_remake_mail_files:
            self.remake_mail_files(None)
            executor.create_command("doms_runner_user_update", "root", {"verb": "install_mail_files"})

        if self.need_remake_system_files:
            self.remake_unix_files(None)
            executor.create_command("doms_runner_user_update", "root", {"verb": "install_passwd_files"})

        self.need_remake_system_files = self.need_remake_mail_files = False

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
        this_user["events"].append({"when_dt": misc.now(), "desc": f"Domain '{domain}' is now active"})

        log.debug(f"check_one_domain PASS: {this_user['user']}, {domain}")
        # CODE - email user a new domain is now active, if secondary domain!
        return True

    def email_users_welcome(self, data):
        for user in self.users_to_welcome:
            log.debug(f"Email welcome to '{user}'")
        self.users_to_welcome = []
        # CODE - send out welcome email
        return True

    def identity_changed(self, data):
        emails = [
            item["Email"].rstrip(".")
            for item in json.loads(base64.b64decode(data.get("identities", "{}")).decode("utf-8"))
        ]
        if (user := base64.b64decode(data.get("user", None)).decode("utf-8")) is None:
            return False

        user = misc.utf8_to_puny(user.rstrip(".").lower())
        if user not in self.all_users:
            log.log(f"ERROR: user '{user}' does not seem to exist")
            return False

        emails = clean_up_emails(emails)

        log.debug(f"USER:{user} EMAILS:{emails}")

        this_user = self.all_users[user]
        old_user = this_user.copy()

        default_mail_domain = policy.get("default_mail_domain").rstrip(".").lower()

        this_user["identities"] = [user + "@" + dom for user, dom in emails]
        email_doms = [dom for __, dom in emails if dom != default_mail_domain]

        for dom in list(this_user["domains"]):
            if dom not in email_doms and dom != user:
                del this_user["domains"][dom]

        for dom in email_doms:
            if dom not in this_user["domains"]:
                this_user["domains"][dom] = False

        this_user["identities"].sort()
        if not user_has_changed(old_user, this_user):
            log.debug("User hasn't changed")
            return True

        self.need_remake_mail_files = True
        this_user["events"].append({"when_dt": misc.now(), "desc": "Email Identities updated"})
        filecfg.record_info_update("users", this_user["user"], {
            "events": this_user["events"],
            "identities": this_user["identities"],
            "domains": this_user["domains"]
        })

        self.run_mx_check(this_user)
        return True

    def new_user_added(self, data):
        if (user := data.get("user", None)) is None:
            return False
        if (this_user := filecfg.record_info_load("users", user)) is None:
            return False
        this_user["user"] = user
        self.all_users[user] = this_user
        return True

    def start_up_new_files(self, data):
        self.remake_unix_files(None)
        self.remake_mail_files(None)
        return True

    def dispatch_job(self, verb, data):
        self.need_remake_mail_files = self.need_remake_system_files = False
        if DOMS_CMDS[verb](data):
            self.check_remake_files()
        else:
            log.log(f"ERROR: cmd '{verb}' failed")
            time.sleep(5)


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
    "remake_unix_files": Users.remake_unix_files,
    "remake_mail_files": Users.remake_mail_files,
    "start_up_new_files": Users.start_up_new_files,
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
                Users.dispatch_job(cmd_data["verb"], cmd_data.get("data", None))


def run_tests():
    Users.startup()
    for user in Users.all_users:
        user_data = Users.all_users[user]
        for email in user_data["identities"]:
            print(user_data["uid"], user, email, validation.is_email_active(user_data, email))


def main():
    parser = argparse.ArgumentParser(description='DOMS Jobs Runner')
    parser.add_argument("-D", "--debug", default=False, help="Debug mode", action="store_true")
    parser.add_argument("-S", "--syslog", default=False, help="With syslog", action="store_true")
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    parser.add_argument("-O", "--one", help="Run one module")
    parser.add_argument("-d", "--data", help="data for running one")
    args = parser.parse_args()

    Users.startup()

    if args.one:
        log.init("DOMS run one", with_debug=True, with_logging=args.syslog)
        if args.one not in DOMS_CMDS:
            log.log("ERROR: DOMS CMD '{args.one}' not valid")
            return
        Users.dispatch_job(args.one, json.loads(args.data) if args.data else None)

    elif args.test:
        log.init("DOMS run test", with_debug=True, with_logging=args.syslog)
        run_tests()

    else:
        runner(args.debug, args.syslog)


if __name__ == "__main__":
    main()
