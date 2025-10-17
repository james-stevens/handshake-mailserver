#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import json
import sys

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
DOMAINS_FILE = os.path.join(BASE, "service", "used_domains.json")


class Policy:
    """ policy values manager """
    def __init__(self):
        self.BASE = BASE
        self.POLICY_FILE = POLICY_FILE
        self.DOMAINS_FILE = DOMAINS_FILE
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

if __name__ == "__main__":
    print(this_policy.get(sys.argv[1]))
