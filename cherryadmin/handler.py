import time
import json

import cherrypy
import jinja2

try:
    import htmlmin
    has_htmlmin = True
except ImportError:
    has_htmlmin = False

from nxtools import (
    format_time,
    format_filesize,
    s2tc,
    slugify,
    s2time,
    s2words,
    string2color,
    logging,
    log_traceback
)

from .view import CherryAdminView
from .context import CherryAdminContext
from .stats import request_stats


def json_response(response_code=200, message=None, **kwargs):
    data = {"response": response_code}
    data.update(kwargs)
    if message:
        data["message"] = message
    cherrypy.response.headers["Content-type"] = "application/json"
    cherrypy.response.headers["Connection"] = "keep-alive"
    cherrypy.response.headers["Cache-Control"] = "no-cache"
    return json.dumps(data).encode("utf-8")


def save_session_cookie(handler, session_id):
    cookie = cherrypy.response.cookie
    cookie["session_id"] = session_id
    cookie["session_id"]['path'] = '/'
    cookie["session_id"]['max-age'] = handler.parent["sessions_timeout"] * 60
    cookie["session_id"]['version'] = 1


def parse_request(**kwargs):
    data = kwargs

    if cherrypy.request.method == "POST":
        try:
            raw_body = cherrypy.request.body.read().decode("utf-8")
            if raw_body.strip():
                data.update(json.loads(raw_body))
        except Exception:
            pass
    if not data.get("session_id", None):
        try:
            data["session_id"] = cherrypy.request.cookie["session_id"].value
        except KeyError:
            pass
        except Exception:
            log_traceback()
    return data


def get_client_info():
    if "User-Agent" in cherrypy.request.headers:
        user_agent = cherrypy.request.headers["User-Agent"]
    if "X-Real-Ip" in cherrypy.request.headers:
        ip = cherrypy.request.headers["X-Real-Ip"]
    else:
        ip = cherrypy.request.headers["Remote-Addr"]
    return {
        "ip": ip,
        "user_agent": user_agent
    }


class CherryAdminHandler(object):
    def __init__(self, parent):
        self.parent = parent
        self.jinja = jinja2.Environment(
                loader=jinja2.FileSystemLoader(parent["templates_dir"])
            )
        self.jinja.filters["format_time"] = format_time
        self.jinja.filters["format_filesize"] = format_filesize
        self.jinja.filters["s2tc"] = s2tc
        self.jinja.filters["slugify"] = slugify
        self.jinja.filters["s2time"] = s2time
        self.jinja.filters["s2words"] = s2words
        self.jinja.filters["string2color"] = string2color

    @property
    def sessions(self):
        return self.parent.sessions

    def context(self):
        request = parse_request()
        session_id = request.get("session_id")
        user_data = self.sessions.check(session_id)
        context = CherryAdminContext()
        context.update({
                "settings": self.parent.settings,
                "user": self.parent["user_context_helper"](user_data),
                "site": self.parent["site_context_helper"](),
                "page": self.parent["page_context_helper"](),
                "session_id": session_id
            })
        return context

    def render(self, view):
        cherrypy.response.headers["Content-Type"] = view["page"]["mime"]
        cherrypy.response.status = view["page"]["response_code"]
        if view.is_raw:
            return bytes(view.body, "utf-8")
        if view.template_path:
            with open(view.template_path) as f:
                template = self.jinja.from_string(f.read())
        else:
            template = self.jinja.get_template("{}.html".format(view.view))
        data = template.render(**view.context)
        if has_htmlmin and self.parent["minify_html"]:
            data = htmlmin.minify(
                    data,
                    remove_comments=True,
                    remove_empty_space=True,
                    remove_optional_attribute_quotes=False
                )
        return data

    def render_error(self, response_code, message, traceback=""):
        context = self.context()
        view = CherryAdminView("error", context)
        view["title"] = "Error"
        view.build(
                response_code=response_code,
                message=message,
                traceback=traceback
            )
        if response_code in (401, 403):
            logging.error("Access denied:", cherrypy.request.path_info)
            return self.render(view)
        logging.error("Error {} ({}) processing {} request \"{}\"".format(
                response_code,
                message,
                cherrypy.request.method,
                cherrypy.request.path_info
                )
            )
        if traceback:
            logging.debug(traceback)
        return self.render(view)

    def cherrypy_error(self, status, message, traceback, version):
        return self.render_error(int(status.split()[0]), message, traceback)

    #
    # EXPOSED
    #

    @cherrypy.expose
    def ping(self, **kwargs):
        request = parse_request(**kwargs)
        session_id = request.get("session_id")
        if not session_id:
            msg = "Not logged in - no session ID provided"
            logging.warning("PING:", msg)
            return json_response(401, msg)
        user_data = self.sessions.check(session_id)
        if not user_data:
            msg = f"Not logged in - session {session_id} not found"
            logging.warning("PING:", msg)
            return json_response(401, msg)

        client_info = get_client_info()
        self.sessions.delete(session_id)
        session_id = self.sessions.create(user_data, **client_info)

        save_session_cookie(self, session_id)
        uname = user_data.get("login", "anonymous")
        logging.debug(f"PING: Logged in user {uname}")
        return json_response(200, data=user_data, session_id=session_id)

    @cherrypy.expose
    def login(self, *args, **kwargs):
        if args:
            return self.render_error(400, "Bad request")
        if cherrypy.request.method != "POST":
            return self.render_error(400, "Bad request")
        request = parse_request(**kwargs)
        login = request.get("login", "-")
        password = request.get("password", "-")
        user_data = self.parent["login_helper"](login, password)

        if not user_data:
            logging.error(f"Incorrect login ({login})")
            if kwargs.get("api", False):
                return json_response(
                    401, "Invalid user name / password combination"
                )
            return self.default(error="Invalid login/password combination")

        if "password" in user_data:
            del(user_data["password"])

        client_info = get_client_info()

        logging.goodnews("User {} logged in".format(login))
        session_id = self.sessions.create(user_data, **client_info)
        save_session_cookie(self, session_id)

        if request.get("api", False):
            return json_response(200, data=user_data, session_id=session_id)
        raise cherrypy.HTTPRedirect(request.get("from_page", "/"))

    @cherrypy.expose
    def logout(self, **kwargs):
        request = parse_request(**kwargs)
        session_id = request.get("session_id")
        if session_id:
            self.sessions.delete(session_id)
        if request.get("api"):
            return json_response(200, "Logged out")
        else:
            raise cherrypy.HTTPRedirect("/")

    @cherrypy.expose
    def default(self, *args, **kwargs):
        start_time = time.time()
        if not args:
            view_name = "index"
        else:
            try:
                view_name = args[0]
            except IndexError:
                return self.render_error(404, "View is not specified")
            if view_name not in self.parent["views"]:
                return self.render_error(404, f"View '{view_name}' not found")

        context = self.context()
        view_class = self.parent["views"][view_name]
        view = view_class(view_name, context)
        if not view.auth():
            if not view["user"]:
                view = CherryAdminView("login", context)
                view["title"] = "Login"
                if view_name != "index":
                    view["response_code"] = 401
                if kwargs.get("error"):
                    view["error"] = kwargs.get("error")

                view.build()
                return self.render(view)
            return self.render_error(
                403, "You are not authorized to view this page"
            )

        save_session_cookie(self, context["session_id"])

        view.build(*args, **kwargs)
        view["build_time"] = round(time.time() - start_time, 3)
        return self.render(view)

    @cherrypy.expose
    def api(self, *args, **kwargs):
        if not args:
            return json_response(400, "Bad request. No method specified.")
        else:
            try:
                api_method_name = args[0]
            except IndexError:
                return json_response(404, "No API endpoint specified")

            if api_method_name not in self.parent["api_methods"]:
                return json_response(
                    404, f"{api_method_name} endpoint not found"
                )

        try:
            api_method = self.parent["api_methods"][api_method_name]
        except Exception:
            log_traceback()
            return json_response(500)

        request = parse_request(**kwargs)
        user_data = self.sessions.check(request.get("session_id"))
        request["user"] = self.parent["user_context_helper"](user_data)
        user_name = user_data.get("login", "unknown user") \
            if user_data else "anonymous"

        if hasattr(api_method, "silent") and api_method.silent:
            pass
        else:
            logging.info(f"{user_name} requested api method {api_method_name}")

            if user_name not in request_stats:
                request_stats[user_name] = {}
            if api_method_name not in request_stats[user_name]:
                request_stats[user_name][api_method_name] = 0
            request_stats[user_name][api_method_name] += 1

        try:
            response = api_method(**request)

            mime = False
            if hasattr(response, "mime"):
                mime = response.mime

            headers = {
                "Connection": "keep-alive",
                "Cache-Control": "no-cache"
            }

            if hasattr(response, "headers"):
                headers.update(response.headers)

            if hasattr(response, "payload"):
                response = response.payload

            if hasattr(response, "dict"):
                response = response.dict

            if type(response) in [list, dict]:
                mime = "application/json"

            if type(response) == dict and response.get("http_error"):
                cherrypy.response.status = response.get("response")
                del(response["http_error"])

            cherrypy.response.headers["Content-Type"] = mime
            for header in headers:
                cherrypy.response.headers[header] = headers[header]

            if mime == "application/json":
                if response.get("response", 200) >= 400:
                    uname = user_data.get("login", "unknown user") \
                        if user_data else "anonymous"
                    logging.error(
                        "API Request '{}' by {} failed with code ".format(
                                api_method_name,
                                uname,
                            ),
                        response.get("response"),
                        response.get("message", "Unknown error")
                    )
                return json.dumps(response).encode("utf-8")
            return response

        except cherrypy.CherryPyException:
            raise

        except Exception:
            message = log_traceback("Exception")
            return json_response(500, message)
