#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information

import os
import jinja2
import argparse

from policy import this_policy as policy

SRC_DIR = "/usr/local/etc/templates"
DST_DIR = "/run/templates"


def main():
    if not os.path.isdir(DST_DIR):
        os.mkdir(DST_DIR, mode=0o755)

    merge_data = {"policy": policy.data()}

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
    print(policy.get("strict_referrer"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ROOT Jobs Runner')
    parser.add_argument("-T", "--test", default=False, help="Run tests", action="store_true")
    args = parser.parse_args()
    if args.test:
        run_tests()
    else:
        main()
