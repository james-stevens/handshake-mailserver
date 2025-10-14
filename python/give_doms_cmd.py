#! /usr/bin/python3

import sys
import executor
import doms_runner
import log

if len(sys.argv) == 2 and sys.argv[1] in doms_runner.DOMS_CMDS:
    executor.create_command("give_doms_cmd", "doms", {"verb": sys.argv[1]})
else:
    log.init("give dom cmd")
    log.log("ERROR: no command or command invalid")
