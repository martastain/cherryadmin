import re
import time
import json

import cherrypy
import jinja2

try:
    import htmlmin
    has_htmlmin = True
except ImportError:
    has_htmlmin = False

from nxtools import *

from .view import *
from .context import *


def json_response(response_code=200, message=None, **kwargs):
    data = {"response" : response_code}
    data.update(kwargs)
    if message:
        data["message"] = message
    cherrypy.response.headers["Content-type"] = "application/json"
    cherrypy.response.headers["Connection"] =  "keep-alive"
    cherrypy.response.headers["Cache-Control"] =  "no-cache"
    return encode_if_py3(json.dumps(data))


def save_session_cookie(session_id):
    cookie = cherrypy.response.cookie
    cookie["session_id"] = session_id
    cookie["session_id"]['path'] = '/'
    cookie["session_id"]['max-age'] = 3600*24
    cookie["session_id"]['version'] = 1


def parse_request(**kwargs):
    data = kwargs
    if cherrypy.request.method == "POST":
        try:
            raw_body = decode_if_py3(cherrypy.request.body.read())
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
                "user" : self.parent["user_context_helper"](user_data),
                "site" : self.parent["site_context_helper"](),
                "page" : self.parent["page_context_helper"](),
                "session_id" : session_id
            })
        return context


    def render(self, view):
        cherrypy.response.headers["Content-Type"] = view["page"]["mime"]
        if view.is_raw:
            return encode_if_py3(view.body)
        template = self.jinja.get_template("{}.html".format(view.view))
        data = template.render(**view.context)
        if has_htmlmin and self.parent["minify_html"]:
            data = htmlmin.minify(data, remove_comments=True, remove_empty_space=True)
        return data


    def render_error(self, response_code, message, traceback=""):
        cherrypy.response.status = response_code
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
        logging.error("Error {} ({}) during processing {} request \"{}\"".format(
                response_code,
                message,
                cherrypy.request.method,
                cherrypy.request.path_info
                )
            )
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
            return json_response(401, "Not logged in - no session ID provided")
        user_data = self.sessions.check(session_id)
        if not user_data:
            return json_response(401, "Not logged in - session not found")

        self.sessions.update(session_id, user_data)
        save_session_cookie(session_id)
        return json_response(200, user=user_data)


    @cherrypy.expose
    def login(self, **kwargs):
        if cherrypy.request.method != "POST":
            return self.render_error(400, "Bad request")
        request = parse_request(**kwargs)
        login = request.get("login", "-")
        password = request.get("password", "-")
        user_data = self.parent["login_helper"](login, password)

        if not user_data:
            if kwargs.get("api", False):
                return json_response(401, "Invalid user name / password combination")
            return self.default(error="Invalid login/password combination")
            raise cherrypy.HTTPRedirect("/")

        if "password" in user_data:
            del(user_data["password"])

        session_id = self.sessions.create(user_data)
        save_session_cookie(session_id)

        if kwargs.get("api", False):
            return json_response(200, data=user_data, session_id=session_id)
        raise cherrypy.HTTPRedirect(request.get("from_page", "/"))


    @cherrypy.expose
    def logout(self, **kwargs):
        request = parse_request(**kwargs)
        session_id = request.get("session_id")
        if session_id:
            self.sessions.delete(session_id)
        if kwargs.get("api"):
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
                if not view_name in self.parent["views"]:
                    raise IndexError
            except IndexError:
                return self.render_error(404, "\"{}\" module not found".format(view_name))

        view_class = self.parent["views"][view_name]
        view = view_class(view_name, self.context())
        context = self.context()
        if not view.auth():
            if not view["user"]:
                cherrypy.response.status = 401
                context["page"]["title"] = "Login"
                msg = kwargs.get("error")
                if msg:
                    context["page"]["error"] = msg
                view = CherryAdminView("login", context)
                view.build()
                return self.render(view)
            return self.render_error(403, "You are not authorized to view this page")


        save_session_cookie(context["session_id"])

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
                if not api_method_name in self.parent["api_methods"]:
                    raise KeyError
            except KeyError:
                return json_response(404, "{} api method not found".format(api_method_name))

        request = parse_request(**kwargs)
        user_data = self.sessions.check(request.get("session_id"))
        request["user"] = self.parent["user_context_helper"](user_data)

        logging.info("{} requested api method {}".format(user_data.get("login", "anonymous"), api_method_name))

        try:
            api_method = self.parent["api_methods"][api_method_name]
            response = api_method(**request)

            mime = False
            if hasattr(response, "mime"):
                mime = response.mime

            headers = {
                    "Connection" :"keep-alive",
                    "Cache-Control" :"no-cache"
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
                    logging.error(
                            "API Request '{}' by {} failed with code ".format(
                                    api_method_name,
                                    user_data.get("login", "anonymous"),
                                ),
                            response.get("response"),
                            response.get("message", "Unknown error")
                        )
                return encode_if_py3(json.dumps(response))
            return response

        except cherrypy.CherryPyException:
            raise

        except Exception:
            message = log_traceback("Exception")
            return json_response(500, message)
