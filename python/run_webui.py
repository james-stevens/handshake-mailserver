#! /usr/bin/python3
# (c) Copyright 2019-2022, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information
""" module to run the rest/api for user's site web/ui """

import flask

import log
import users
import policy

WANT_REFERRER_CHECK = True

HTML_CODE_ERR = 499
HTML_CODE_OK = 200

NOT_LOGGED_IN = "Not logged in or login timed-out"

SESSION_TAG = "X-Session-Code"
SESSION_TAG_LOWER = SESSION_TAG.lower()

log.init("logging_webui")
application = flask.Flask("EPP Registrar")


class WebuiReq:
    """ data unique to each request to keep different users data separate """
    def __init__(self):
        self.sess_code = None
        self.user_id = None
        self.user_data = None
        self.post_js = flask.request.json if flask.request.method == "POST" and flask.request.is_json else None
        self.headers = {item.lower(): val for item, val in dict(flask.request.headers).items()}
        self.user_agent = self.headers.get("user-agent", "Unknown")

        if SESSION_TAG_LOWER in self.headers:
            logged_in, check_sess_data = users.check_session(self.headers[SESSION_TAG_LOWER], self.user_agent)
            self.parse_user_data(logged_in, check_sess_data)

        self.base_event = self.set_base_event()
        self.is_logged_in = (self.user_id is not None and self.sess_code is not None)

    def parse_user_data(self, logged_in, check_sess_data):
        """ set up session properties """
        if not logged_in or "session" not in check_sess_data:
            return

        self.user_data = check_sess_data
        self.sess_code = check_sess_data["session"]
        self.user_id = check_sess_data['user_id']
        log.debug(f"Logged in as {self.user_id}")

    def abort(self, data):
        """ return error code to caller """
        return self.response({"error": data}, HTML_CODE_ERR)

    def response(self, data, code=HTML_CODE_OK):
        """ return OK response & data to caller """
        self.secure_user_data()
        resp = flask.make_response(flask.jsonify(data), code)
        resp.charset = 'utf-8'
        if self.sess_code is not None:
            resp.headers[SESSION_TAG] = self.sess_code
        return resp


@application.before_request
def before_request():
    strict_referrer = policy.policy("strict_referrer")
    if strict_referrer is not None and not strict_referrer:
        return None

    allowable_referrer = policy.policy("allowable_referrer")
    if allowable_referrer is not None and isinstance(allowable_referrer, (dict, list)):
        if flask.request.referrer in allowable_referrer:
            return None
    elif flask.request.referrer == "https://" + policy.policy("website_name") + "/":
        return None

    return flask.make_response(flask.jsonify({"error": "Website continuity error"}), HTML_CODE_ERR)


@application.route('/pyrar/v1.0/hello', methods=['GET'])
def hello():
    req = WebuiReq()
    return req.response({"hello": "world"})


@application.route('/pyrar/v1.0/users/update', methods=['POST'])
def users_update():
    req = WebuiReq()
    if not req.is_logged_in:
        return req.abort(NOT_LOGGED_IN)

    if req.post_js is None:
        return req.abort("No JSON posted")

    ret, user_data = users.update_user(req.user_id, req.post_js)
    if not ret:
        return req.abort(user_data)

    req.user_data["user"] = user_data
    return req.send_user_data()


@application.route('/pyrar/v1.0/users/password', methods=['POST'])
def users_password():
    req = WebuiReq()
    if not req.is_logged_in:
        return req.abort(NOT_LOGGED_IN)

    if not users.check_password(req.user_id, req.post_js):
        return req.abort("Password match failed")

    users.passwd_new(req.post_js["new_password"])

    return req.response("OK")


@application.route('/pyrar/v1.0/users/login', methods=['POST'])
def users_login():
    req = WebuiReq()
    if req.post_js is None:
        return req.abort("No JSON posted")

    ret, data = users.login(req.post_js, req.user_agent)
    if not ret or not data:
        return req.abort("Login failed")

    req.parse_user_data(ret, data)

    return req.response(data)


@application.route('/pyrar/v1.0/users/logout', methods=['GET'])
def users_logout():
    req = WebuiReq()
    if not req.is_logged_in:
        return req.abort(NOT_LOGGED_IN)

    users.logout(req.sess_code, req.user_id, req.user_agent)

    req.sess_code = None
    req.user_id = None

    return req.response("logged-out")


def main():
    global WANT_REFERRER_CHECK
    log.init(with_debug=True)
    WANT_REFERRER_CHECK = False
    application.run()


if __name__ == "__main__":
    log.log("RUNNING WEB/UI")
    main()
