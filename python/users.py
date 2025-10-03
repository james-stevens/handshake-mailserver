#! /usr/bin/python3

import tempfile
import time
import os
import filelock
import json
import passlib.hash

import policy
import executor

USER_FILE = policy.BASE + "/service/users.json"
USER_LOCK = policy.BASE + "/service/users.lock"

SESSION_EXPIRE_TIME = policy.policy("session_expiry")


def login(data, user_agent):
    if data.get("user", None) is None or data.get("password", None) is None:
        return False, None
    if not passwd_compare(data["password"], data["user"]):
        return False, None
    if (ret := user_info_load(data["user"])) is None:
        return False, None

    with tempfile.NamedTemporaryFile("w+", dir="/run/sessions", encoding="utf-8", delete=False, prefix="user_") as fd:
        json.dump({"user": data["user"], "agent": user_agent}, fd)
        session_code = fd.name.split("/")[-1]

    return True, {"user_id": data["user"], "session": session_code, "data": ret}


def check_session(session_code, user_agent):
    file = "/run/sessions/" + session_code
    now = time.time()

    if not os.path.isfile(file):
        return False, None

    if os.path.getmtime(file) + SESSION_EXPIRE_TIME <= now:
        os.remove(file)
        return False, None

    with open(file, "r") as fd:
        js = json.load(fd)

    if "agent" not in js or js["agent"] != user_agent or "user" not in js:
        os.remove(file)
        return False, None

    if (ret := user_info_load(js["user"])) is not None:
        os.utime(file, (now, now))
        return True, ret

    return False, None


def passwd_new(pass_text, user):
    executor.create_command("webui-users", "root", {"name": user, "passwd": pass_text})


def passwd_crypt(pass_text):
    return passlib.hash.sha512_crypt.hash(pass_text, rounds=5000)


def passwd_compare(pass_text, user):
    with open("/etc/shadow", "r") as fd:
        users = [line.strip().split(":") for line in fd.readlines()]
    by_user = {u[0]: u[1:] for u in users}
    if user not in by_user:
        return False
    stored_pass = by_user[user][0].split("$")
    enc_pass = passlib.hash.sha512_crypt.hash(pass_text, rounds=5000, salt=stored_pass[2])
    return by_user[user][0] == enc_pass


def user_info_load(user):
    if not os.path.isfile(USER_FILE):
        return None
    with filelock.FileLock(USER_LOCK), open(USER_FILE, "r") as fd:
        js = json.load(fd)
    return js.get(user, None)


def user_info_update(user, data):
    with filelock.FileLock(USER_LOCK):
        if not os.path.isfile(USER_FILE):
            js = {}
        else:
            with open(USER_FILE, "r") as fd:
                js = json.load(fd)

        if data is None and user in js:
            del js[user]
        else:
            js[user] = data

        with open(USER_FILE, "w") as fd:
            json.dump(js, fd)

    return js.get(user, None)


if __name__ == "__main__":
    # print(user_info_load("james"))
    # print(user_info_update("james", {"name": "james", "password": "fred"}))
    # print(user_info_load("james"))
    # print(user_info_update("james", None))
    # print(user_info_load("james"))
    # print(passwd_compare("yes","lord.webmail"))
    # print(check_session("abc123","fred"))
    ok, uid = login({"user": "lord.webmail", "password": "yes"}, "my-agent")
    print(ok, uid)
    print(check_session(uid["session"], "my-agent"))
