#! /usr/bin/python3
# (c) Copyright 2019-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information
""" functions for sys-logging """

import sys
import syslog
import inspect
import datetime

from policy import this_policy as policy

facility_options = {
    "kern": syslog.LOG_KERN,
    "kernel": syslog.LOG_KERN,
    "user": syslog.LOG_USER,
    "mail": syslog.LOG_MAIL,
    "daemon": syslog.LOG_DAEMON,
    "auth": syslog.LOG_AUTH,
    "syslog": syslog.LOG_SYSLOG,
    "lpr": syslog.LOG_LPR,
    "news": syslog.LOG_NEWS,
    "uucp": syslog.LOG_UUCP,
    "cron": syslog.LOG_CRON,
    "authpriv": syslog.LOG_AUTHPRIV,
    "local0": syslog.LOG_LOCAL0,
    "local1": syslog.LOG_LOCAL1,
    "local2": syslog.LOG_LOCAL2,
    "local3": syslog.LOG_LOCAL3,
    "local4": syslog.LOG_LOCAL4,
    "local5": syslog.LOG_LOCAL5,
    "local6": syslog.LOG_LOCAL6,
    "local7": syslog.LOG_LOCAL7
}

severity_options = {
    "emerg": syslog.LOG_EMERG,
    "emergency": syslog.LOG_EMERG,
    "alert": syslog.LOG_ALERT,
    "crit": syslog.LOG_CRIT,
    "critical": syslog.LOG_CRIT,
    "err": syslog.LOG_ERR,
    "error": syslog.LOG_ERR,
    "warning": syslog.LOG_WARNING,
    "notice": syslog.LOG_NOTICE,
    "info": syslog.LOG_INFO,
    "information": syslog.LOG_INFO,
    "debug": syslog.LOG_DEBUG
}


class Log:
    def __init__(self):
        self.done_init = False
        self.with_debug = False
        self.to_syslog = True

    def debug(self, line):
        if self.with_debug:
            where = inspect.stack()[1]
            self.log(f"[DEUBG] {line}", syslog.LOG_DEBUG, where=where)

    def log(self, line, default_level=syslog.LOG_NOTICE, where=None):
        if where is None:
            where = inspect.stack()[1]
        txt = ""
        if where is not None:
            fname = where.filename.split("/")[-1].split(".")[0]
            txt = f"[{fname}:{str(where.lineno)}/{where.function}]"

        if self.to_syslog:
            if not self.done_init:
                self.init()
            if isinstance(default_level, str):
                default_level = severity_options[default_level]
            syslog.syslog(default_level, f"{txt} {line}")
        else:
            now = datetime.datetime.now()
            now_txt = now.strftime("%Y-%m-%d %H:%M:%S")
            print(f"{now_txt} SYSLOG{txt} {line}")

    def check_off(self, this_facility, also_check_none=False):
        if this_facility in ["None", "Off"] or (also_check_none and this_facility is None):
            self.to_syslog = False
            self.done_init = True
            return True
        return False

    def init(self, inp_facility=None, with_debug=False, to_syslog=True):
        if self.check_off(inp_facility):
            return

        if inp_facility in facility_options:
            this_facility = facility_options[inp_facility]
        else:
            if (this_facility := policy.get(inp_facility)) is None:
                this_facility = policy.get("logging_default")

        if self.check_off(this_facility, True):
            return

        if this_facility in facility_options:
            this_facility = facility_options[this_facility]

        syslog.openlog(logoption=syslog.LOG_PID, facility=this_facility)
        self.to_syslog = to_syslog
        self.with_debug = with_debug
        self.done_init = True


this_log = Log()

if __name__ == "__main__":
    this_log.init(sys.argv[0], with_debug=True, to_syslog=False)
    this_log.log("Hello 1")
    this_log.debug("Hello 2")
    this_log.to_syslog = True
    this_log.log("Sys Hello 1")
    this_log.debug("Sys Hello 2")
