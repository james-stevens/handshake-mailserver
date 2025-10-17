#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import tempfile
import time
import os
import json
import passlib.hash
import hashlib
import secrets
import base64
import validators

from policy import this_policy as policy
import executor
import validation
import usercfg
import misc
# from log import this_log as log

USER_FILE = policy.BASE + "/service/users.json"
SESSIONS_DIR = "/run/sessions"

SESSION_EXPIRE_TIME = policy.get("session_expiry")


def make_session_code(user):
    """ make a user's session code - sent to the user """
    hsh = hashlib.sha256()
    hsh.update(secrets.token_bytes(500))
    hsh.update(str(user).encode("utf-8"))
    hsh.update(str(os.getpid()).encode("utf-8"))
    hsh.update(str(time.time()).encode("utf-8"))
    return base64.b64encode(hsh.digest()).decode("utf-8").translate(str.maketrans({"/": "-", "=": "", "+": "_"}))


def encrypt(password, salt=None):
    return passlib.hash.sha512_crypt.hash(password, rounds=5000, salt=salt)


def compare_passwords(plaintext, stored):
    parts = stored.split("$")
    return encrypt(plaintext, parts[2]) == stored


def create_session_file(user, user_data, user_agent):
    with tempfile.NamedTemporaryFile("w+",
                                     dir=SESSIONS_DIR,
                                     encoding="utf-8",
                                     delete=False,
                                     prefix=make_session_code(user)) as fd:
        json.dump({"user": user, "agent": user_agent}, fd)
        session_code = fd.name.split("/")[-1]

    user_data["session"] = session_code
    user_data["user"] = user

    return True, user_data


def login(sent_data, user_agent):
    if sent_data.get("user", None) is None or sent_data.get("password", None) is None:
        return False, "Insufficient data"

    ok, user_data = usercfg.user_info_load(sent_data["user"])
    if not ok or user_data is None or "password" not in user_data:
        return False, f"User '{sent_data['user']}' not found or missing password"

    if not compare_passwords(sent_data["password"], user_data["password"]):
        return False, "Password does no match"

    usercfg.user_info_update(sent_data["user"], {"last_login_dt": misc.now()})
    return create_session_file(sent_data["user"], user_data, user_agent)


def check_session(session_code, user_agent):
    file = SESSIONS_DIR + "/" + session_code
    now = time.time()

    if not os.path.isfile(file):
        return False, f"Session file '{file}' missing"

    if os.path.getmtime(file) + SESSION_EXPIRE_TIME <= now:
        os.remove(file)
        return False, "Session file too old"

    with open(file, "r") as fd:
        js = json.load(fd)

    if "agent" not in js or js["agent"] != user_agent or "user" not in js:
        os.remove(file)
        return False, "Session file missing data or user-agent mismatch"

    ok, user_data = usercfg.user_info_load(js["user"])
    if not ok or user_data is None:
        return False, "User in session file doesn't exist"

    os.utime(file, (now, now))
    user_data["session"] = session_code

    return True, user_data


def check_password(user, sent_data):
    ok, user_data = usercfg.user_info_load(user)
    return compare_passwords(sent_data["password"], user_data["password"])


def logout(session_code, user, user_agent):
    ok, user_data = check_session(session_code, user_agent)
    if not ok or user_data is None:
        return False, "Session code failed to checkout"

    os.remove(SESSIONS_DIR + "/" + session_code)
    return True, None


REGISTER_WEB = {
    "user": [True, validation.web_valid_new_account],
    "email": [True, validators.email],
    "password": [True, None],
    "confirm": [True, None]
}


def register(sent_data, user_agent):
    ok, reply = validation.web_validate(sent_data, REGISTER_WEB)
    if not ok:
        return False, reply

    if sent_data["password"] != sent_data["confirm"]:
        return False, "Passwords do not match"

    user = sent_data["user"]
    now = misc.now()
    user_data = {
        "mx": base64.b32encode(secrets.token_bytes(30)).decode("utf-8").lower(),
        "password": encrypt(sent_data["password"]),
        "created_dt": now,
        "amended_dt": now,
        "last_login_dt": now,
        "email": sent_data["email"],
        "events": [{
            "when_dt": now,
            "desc": "Account first registered"
        }],
        "identities": [],
        "domains": {
            user: False
        }
    }

    file, __ = usercfg.user_file_name(user, True)
    with open(file, "w+") as fd:
        json.dump(user_data, fd, indent=2)

    executor.create_command("new_user_added", "doms", {"verb": "new_user_added"})
    return create_session_file(user, user_data, user_agent)


def password_new(password):
    # CODE - change password
    pass


if __name__ == "__main__":
    print("INFO LOAD ->", usercfg.user_info_load("lord.webmail"))


def debug_stuff():
    print(
        "REGISTER >>>",
        register({
            "user": "anon.webmail",
            "email": "earl@gmail.com",
            "password": "yes",
            "confirm": "yes"
        }, "my-agent"))
    print("--->>>", USER_FILE)
    # print(usercfg.user_info_load("james"))
    # print(usercfg.user_info_update("james", {"user": "james", "password": "fred"}))
    # print(usercfg.user_info_load("james"))
    # print(usercfg.user_info_update("james", None))
    # print(usercfg.user_info_load("james"))
    # print(password_compare("yes","lord.webmail"))
    # print(check_session("abc123","fred"))

    ok, uid = login({"user": "lord.webmail", "password": "yes"}, "my-agent")
    print("LOGIN ->", ok, uid)
    if ok:
        print("CHECK_SESSION ->", check_session(uid["session"], "my-agent"))

    print("")
    print("INFO LOAD ->", usercfg.user_info_load("lord.webmail"))
    print("INFO ADD ->", usercfg.user_info_update("lord.webmail", {"temp": "value"}))
    print("INFO LOAD ->", usercfg.user_info_load("lord.webmail"))
    print("INFO ADD ->", usercfg.user_info_update("lord.webmail", {"temp": None}))
    print("INFO LOAD ->", usercfg.user_info_load("lord.webmail"))
    # print(make_session_code("james"))
