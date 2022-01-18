import os
import time
import json
import hashlib

from nxtools import log_traceback, critical_error, logging, get_guid


class CherryAdminSessions():
    def __init__(self, sessions_dir, max_age, salt):
        self.sessions_dir = str(sessions_dir)
        self.max_age = max_age
        self.salt = salt

        if not os.path.isdir(self.sessions_dir):
            try:
                os.makedirs(self.sessions_dir)
            except Exception:
                critical_error(
                    f"Unable to create sessions directory {self.sessions_dir}"
                )

    def load(self, session_id):
        if not session_id:
            return False
        try:
            with open(os.path.join(self.sessions_dir, session_id)) as f:
                data = json.load(f)
            return data
        except Exception:
            return False

    def save(self, session_id, data):
        try:
            with open(os.path.join(self.sessions_dir, session_id), "w") as f:
                json.dump(data, f)
        except Exception:
            log_traceback()
            return False
        return True

    def delete(self, session_id):
        try:
            os.remove(os.path.join(self.sessions_dir, session_id))
        except Exception:
            pass

    def check(self, session_id, extend=False):
        data = self.load(session_id)
        if not data:
            return False
        age = time.time() - data.get("ctime", 0)
        if age > self.max_age:
            logging.debug(f"Session {session_id} has expired. Removing.")
            self.delete(session_id)
            return False
        if age > self.max_age/2:
            extend = True
        if extend:
            data["ctime"] = time.time()
            self.save(session_id, data)
        return data["user_data"]

    def create(self, user_data, **kwargs):
        session_id = self.create_session_id()
        data = {
            "user_data": user_data,
            "ctime": time.time(),
        }
        data.update(kwargs)
        if self.save(session_id, data):
            return session_id
        return False

    def update(self, session_id, user_data, **kwargs):
        data = {
            "user_data": user_data,
            "ctime": time.time()
        }
        data.update(kwargs)
        if self.save(session_id, data):
            return session_id
        return False

    def create_session_id(self):
        string = get_guid() + self.salt
        string = bytes(string, "utf-8")
        return hashlib.sha256(string).hexdigest()
