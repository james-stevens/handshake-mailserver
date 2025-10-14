#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import json
import jinja2
import argparse

import fileloader

DEFAULT_POLICY_VALUES = {
    "default_mail_domain": "webmail.localhost",
    "mx_mail_domain": "mx.example.com",
    "website_domain": "example.com",
    "website_title": "Handshake Webmail",
    "site_fqdn": "handshake.webmail",
    "site_country": "GB",
    "site_location": "London",
    "site_org": "Handshake",
    "site_org_unit": "Ops",
    "site_state": "London",
    "logging_default": "local0",
    "strict_referrer": True,
    "allow_icann_domains": False,
    "allowable_referrer": None,
    "session_expiry": 60 * 60 * 2
}

BASE = os.environ.get("BASE", "/opt/data")
POLICY_FILE = os.path.join(BASE, "service", "policy.json")
SRC_DIR = "/usr/local/etc/templates"
DST_DIR = "/run/templates"


class Policy:
    """ policy values manager """
    def __init__(self):
        self.BASE = BASE
        self.POLICY_FILE = POLICY_FILE
        if not os.path.isfile(POLICY_FILE):
            with open(POLICY_FILE, "w+") as fd:
                json.dump(DEFAULT_POLICY_VALUES, fd, indent=2)

        self.file = fileloader.FileLoader(POLICY_FILE)
        self.all_data = None
        self.merge_policy_data()

    def merge_policy_data(self):
        self.all_data = DEFAULT_POLICY_VALUES.copy()
        self.all_data.update(self.file.data())

    def check_file(self):
        if self.file.check_for_new():
            self.merge_policy_data()

    def get(self, name, default_value=None):
        self.check_file()
        return self.all_data.get(name, default_value)

    def data(self):
        self.check_file()
        return self.all_data


this_policy = Policy()


def main():
    if not os.path.isdir(DST_DIR):
        os.mkdir(DST_DIR, mode=0o755)

    merge_data = {"policy": this_policy.data()}
    for item in DEFAULT_POLICY_VALUES:
        if merge_data["policy"][item] is None or merge_data["policy"][item] == "":
            merge_data["policy"][item] = DEFAULT_POLICY_VALUES[item]

    environment = jinja2.Environment(loader=jinja2.FileSystemLoader(SRC_DIR))
    for file in os.listdir(SRC_DIR):
        if os.path.isfile(os.path.join(SRC_DIR, file)):
            dst_path = os.path.join(DST_DIR, file)
            template = environment.get_template(file)
            content = template.render(**merge_data)
            with open(dst_path, "w", encoding="UTF-8") as fd:
                fd.write(content)

    with open(DST_DIR + "/__include__", "w+") as fd:
        for item in merge_data["policy"]:
            fd.write(f"export POLICY_{item.upper()}='{merge_data['policy'][item]}'\n")


def run_tests():
    print(json.dumps(DEFAULT_POLICY_VALUES, indent=2))
    print("====================================")
    print(this_policy.get("strict_referrer"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ROOT Jobs Runner')
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    args = parser.parse_args()
    if args.test:
        run_tests()
    else:
        main()
