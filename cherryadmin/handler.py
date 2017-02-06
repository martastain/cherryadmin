import time
import json

import cherrypy
import jinja2

from nxtools import *

from .common import *
from .context import CherryAdminContext
from .view import CherryAdminView


class CherryAdminHandler(object):
    def __init__(self, parent):
        self.parent = parent
        self.jinja = jinja2.Environment(
                loader=jinja2.FileSystemLoader(parent["templates_dir"])
            )

    def context(self):
        try:
            user_data = json.loads(cherrypy.session["user_data"])
        except Exception:
            user_data = {}
        context = CherryAdminContext()
        context.update({
                "user" : user_data,
                "site" : self.parent["site_context_helper"](),
                "page" : self.parent["page_context_helper"](),
            })
        return context


    def render(self, view):
        template = self.jinja.get_template("{}.html".format(view.name))
        return template.render(**view.context)


    def render_error(self, response_code, message):
        cherrypy.response.status = response_code
        context = self.context()
        view = CherryAdminView("error", context)
        view.build(
                response_code=response_code,
                message=message
            )
        return self.render(view)

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
                return json.dumps({"response" : 401, "message" : "Invalid user name / password combination", "data" : {}})
            raise cherrypy.HTTPRedirect("/")
        cherrypy.session["user_data"] = json.dumps(user)
        if kwargs.get("api", False):
            return json.dumps({"response" : 200, "data" : user})
        raise cherrypy.HTTPRedirect(kwargs.get("from_page", "/"))


    @cherrypy.expose
    def logout(self, **kwargs):
        cherrypy.session["user_data"] = False
        cherrypy.lib.sessions.expire()
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
                view = CherryAdminView("login", self.context())
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
            user_data = json.loads(cherrypy.session["user_data"])
        except Exception:
            user_data = {}
        return json.dumps({"response" : 200, "user" : user_data})


    @cherrypy.expose
    def api(self, *args, **kwargs):
        for key, value in api_headers:
            cherrypy.response.headers[key] = value

        if not args:
            return json.dumps({"response" : 400, "message" : "Bad request. No method specified."})
        else:
            try:
                api_method_name = args[0]
                if not api_method_name in self.parent["api_methods"]:
                    raise KeyError
            except KeyError:
                return json.dumps({"response" : 404, "message" : "\"{}\" api method not found".format(api_method_name)})
        logging.info("Requested api method", api_method_name)

        if cherrypy.request.method != "POST":
            return json.dumps({"response" : 400, "message" : "Bad request. Post expected."})

        try:
            raw_body = cherrypy.request.body.read()
            kwargs = json.loads(raw_body)
        except:
            message = log_traceback("Bad request")
            return json.dumps({"response" : 400, "message" : message})

        context = self.context()

        try:
            api_method = self.parent["api_methods"][api_method_name]
            return json.dumps(api_method(**kwargs))
        except:
            message = log_traceback("Exception")
            return json.dumps({"response" : 500, "message" : message})
