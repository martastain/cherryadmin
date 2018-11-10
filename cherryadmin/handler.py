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

from .common import *
from .view import *
from .context import *



def dump_json(data):
    return encode_if_py3(json.dumps(data))

def get_session(handler, id=None):
    if not id:
        return cherrypy.session
    session = cherrypy.lib.sessions.FileSession(
            id=id,
            storage_path=handler.parent.settings["sessions_dir"]
            )
    session.acquire_lock()
    return session


class CherryAdminHandler(object):
    def __init__(self, parent):
        self.parent = parent
        self.jinja = jinja2.Environment(
                loader=jinja2.FileSystemLoader(parent["templates_dir"])
            )

    def context(self):
        try:
            user_data = cherrypy.session["user_data"]
        except KeyError:
            user_data = {}
        except Exception:
            log_traceback()
            user_data = {}
        context = CherryAdminContext()
        context.update({
                "user" : user_data,
                "site" : self.parent["site_context_helper"](),
                "page" : self.parent["page_context_helper"](),
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


    def render_error(self, response_code, message):
        cherrypy.response.status = response_code
        context = self.context()
        view = CherryAdminView("error", context)
        view["title"] = "Error"
        view.build(
                response_code=response_code,
                message=message
            )
        return self.render(view)


    def cherrypy_error(self, status, message, traceback, version):
        return self.render_error(int(status.split()[0]), message)


    #
    # EXPOSED
    #

    @cherrypy.expose
    def login(self, **kwargs):
        if cherrypy.request.method != "POST":
            return self.render_error(400, "Bad request")
        login = kwargs.get("login", "-")
        password = kwargs.get("password", "-")
        user = self.parent["login_helper"](login, password)
        if not user:
            if kwargs.get("api", False):
                return dump_json({
                        "response" : 401,
                        "message" : "Invalid user name / password combination",
                        "data" : {},
                        "session_id" : cherrypy.session.id
                    })
            raise cherrypy.HTTPRedirect("/")
        cherrypy.session["user_data"] = user
        if kwargs.get("api", False):
            return dump_json({
                "response" : 200,
                "data" : user,
                "session_id" : cherrypy.session.id
                })
        raise cherrypy.HTTPRedirect(kwargs.get("from_page", "/"))


    @cherrypy.expose
    def logout(self, **kwargs):
        session = get_session(self, kwargs.get("session_id", None))
        session["user_data"] = False
        session.delete()
        if kwargs.get("api"):
            return dump_json({"response" : 200, "message" : "Logged out"})
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
        if not view.auth():
            if not view["user"]:
                cherrypy.response.status = 401
                context = self.context()
                context["page"]["title"] = "Login"
                view = CherryAdminView("login", context)
                view.build()
                return self.render(view)
            return self.render_error(403, "You are not authorized to view this page")

        view.build(*args, **kwargs)
        view["build_time"] = round(time.time() - start_time, 3)
        return self.render(view)


    @cherrypy.expose
    def ping(self, *args, **kwargs):
        for key, value in api_headers:
            cherrypy.response.headers[key] = value
        try:
            user_data = cherrypy.session["user_data"]
        except KeyError:
            response = 401
            user_data = {}
        except Exception:
            response = 401
            log_traceback()
            user_data = {}
        else:
            response = 200
        return dump_json({"response" : response, "user" : user_data})


    @cherrypy.expose
    def api(self, *args, **kwargs):
        for key, value in api_headers:
            cherrypy.response.headers[key] = value

        if not args:
            return dump_json({
                    "response" : 400,
                    "message" : "Bad request. No method specified."
                })
        else:
            try:
                api_method_name = args[0]
                if not api_method_name in self.parent["api_methods"]:
                    raise KeyError
            except KeyError:
                return dump_json({
                        "response" : 404,
                        "message" : "\"{}\" api method not found".format(api_method_name)
                    })

        if cherrypy.request.method != "POST":
            return dump_json({
                    "response" : 400,
                    "message" : "Bad request. Post expected."
                })

        try:
            raw_body = decode_if_py3(cherrypy.request.body.read())
            if raw_body.strip():
                kwargs = json.loads(raw_body)
            else:
                kwargs = {}
        except Exception:
            message = log_traceback("Bad request")
            return dump_json({"response" : 400, "message" : message})

        context = self.context()

        session = get_session(self, kwargs.get("session_id", None))

        try:
            user_data = session["user_data"]
        except KeyError:
            user_data = {}
        except Exception:
            log_traceback()
            user_data = {}
        kwargs["user"] = user_data

        logging.info("{} requested api method {}".format(user_data.get("login", "anonymous"), api_method_name))

        try:
            api_method = self.parent["api_methods"][api_method_name]
            response = api_method(**kwargs)
            if type(response) == dict:
                pass
            elif hasattr(response, "dict"):
                response = response.dict
            else:
                response = {
                        "response" : 500,
                        "message" : "Unexpected response from API: {}".format(type(response))
                    }
            if response["response"] >= 400:
                logging.error(response.get("message", "Unknown error"))
            return dump_json(response)
        except Exception:
            message = log_traceback("Exception")
            return dump_json({"response" : 500, "message" : message})
