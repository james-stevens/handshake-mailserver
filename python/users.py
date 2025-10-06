#! /usr/bin/python3

import tempfile
import time
import os
import json
import passlib.hash
import hashlib
import secrets
import base64

import policy
import executor
import filecfg

USER_FILE = policy.BASE + "/service/users.json"
USER_LOCK = "/run/users.lock"
SESSIONS_DIR = "/run/sessions"

SESSION_EXPIRE_TIME = policy.policy("session_expiry")


def make_session_code(user):
    """ make a user's session code - sent to the user """
    hsh = hashlib.sha256()
    hsh.update(secrets.token_bytes(500))
    hsh.update(str(user).encode("utf-8"))
    hsh.update(str(os.getpid()).encode("utf-8"))
    hsh.update(str(time.time()).encode("utf-8"))
    return base64.b64encode(hsh.digest()).decode("utf-8").translate(str.maketrans({"/": "-", "=": "", "+": "_"}))


def login(sent_data, user_agent):
    if sent_data.get("user", None) is None or sent_data.get("password", None) is None:
        return False, "Insufficient data"

    if (user := user_info_load(sent_data["user"], for_login=True)) is None or "password" not in user:
        return False, f"User '{sent_data['user']}' not found or missing password"

    stored_pass = user["password"].split("$")
    enc_pass = passlib.hash.sha512_crypt.hash(sent_data["password"], rounds=5000, salt=stored_pass[2])
    if enc_pass != user["password"]:
        return False, "Password does no match"

    with tempfile.NamedTemporaryFile("w+",
                                     dir=SESSIONS_DIR,
                                     encoding="utf-8",
                                     delete=False,
                                     prefix=make_session_code(sent_data["user"])) as fd:
        json.dump({"user": sent_data["user"], "agent": user_agent}, fd)
        session_code = fd.name.split("/")[-1]

    del user["password"]
    return True, {"user": sent_data["user"], "session": session_code, "data": user}


def check_session(session_code, user_agent):
    file = SESSIONS_DIR + session_code
    now = time.time()

    if not os.path.isfile(file):
        return False, "Session file missing"

    if os.path.getmtime(file) + SESSION_EXPIRE_TIME <= now:
        os.remove(file)
        return False, "Session file too old"

    with open(file, "r") as fd:
        js = json.load(fd)

    if "agent" not in js or js["agent"] != user_agent or "user" not in js:
        os.remove(file)
        return False, "Session file missing data or user-agent mismatch"

    if (user := user_info_load(js["user"])) is None:
        return False, "User in session file is missing"

    os.utime(file, (now, now))
    del user["password"]
    return True, user


def password_new(pass_text, user):
    return executor.create_command("webui-users", "root", {"user": user, "password": pass_text})


def user_info_load(user, for_login=False):
    return filecfg.record_info_load("users", user, for_login)


def user_info_update(user, data):
    return filecfg.record_info_update("users", user, data)


if __name__ == "__main__":
    print("--->>>", USER_FILE)
    # print(user_info_load("james"))
    # print(user_info_update("james", {"user": "james", "password": "fred"}))
    # print(user_info_load("james"))
    # print(user_info_update("james", None))
    # print(user_info_load("james"))
    # print(password_compare("yes","lord.webmail"))
    # print(check_session("abc123","fred"))

    ok, uid = login({"user": "lord.webmail", "password": "yes"}, "my-agent")
    print("LOGIN ->", ok, uid)
    if ok:
        print("CHECK_SESSION ->", check_session(uid["session"], "my-agent"))

    print("")
    print("INFO LOAD ->", user_info_load("lord.webmail"))
    print("INFO ADD ->", user_info_update("lord.webmail", {"temp": "value"}))
    print("INFO LOAD ->", user_info_load("lord.webmail"))
    print("INFO ADD ->", user_info_update("lord.webmail", {"temp": None}))
    print("INFO LOAD ->", user_info_load("lord.webmail"))
    # print(make_session_code("james"))
