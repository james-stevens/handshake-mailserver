#! /usr/bin/python3

import os
import json
import jinja2

DEFAULT_POLICY_VALUES = {
    "default_mail_domain": "webmail.localhost",
    "hosting_domain": "example.com",
    "website_title": "Handshake Webmail",
    "site_fqdn": "handshake.webmail",
    "site_country": "GB",
    "site_location": "London",
    "site_org": "Handshake",
    "site_org_unit": "Ops",
    "site_state": "London"
}

BASE = os.environ.get("BASE", "/opt/data")
SRC_DIR = "/usr/local/etc/templates"
DST_DIR = "/run/templates"


def get_policy_values():
    file = BASE + "/etc/policy.json"
    if os.path.isfile(file):
        with open(file, "r", encoding='UTF-8') as fd:
            new_values = json.load(fd)
    else:
        new_values = {}
    return DEFAULT_POLICY_VALUES | new_values


def main():
    if not os.path.isdir(DST_DIR):
        os.mkdir(DST_DIR, mode=0o755)

    merge_data = {"policy": get_policy_values()}
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


if __name__ == "__main__":
    main()
