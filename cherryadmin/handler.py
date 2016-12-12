import time
import json

import cherrypy
import jinja2

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
            raise cherrypy.HTTPRedirect("/")

        cherrypy.session["user_data"] = json.dumps(user)
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
                view = CherryAdminView("login", self.context())
                view.build()
                return self.render(view)
            return self.render_error(403, "You are not authorized to view this page")

        view.build(*args, **kwargs)
        view["build_time"] = round(time.time() - start_time, 3)
        return self.render(view)



#TODO: rewrite api
    @cherrypy.expose
    def api(self, method=False):
        for key, value in api_headers:
            cherrypy.response.headers[key] = value

        if cherrypy.request.method != "POST":
            return json.dumps({"response" : 400, "message" : "Bad request. Post expected."})

        try:
            content_length = cherrypy.request.headers['Content-Length']
            raw_body = cherrypy.request.body.read(int(content_length))
            kwargs = json.loads(raw_body)
        except:
            message = log_traceback("Bad request")
            return json.dumps({"response" : 400, "message" : message})

        context = self.context()
        if not context["user"]:
            return json.dumps({"response" : 401, "message" : "Not logged in"})

        if method in api_methods:
            try:
                data = api_methods[method](**kwargs)
            except:
                message = log_traceback("Internal server error")
                return json.dumps({"response" : 500, "message" : message})
        return json.dumps(data)
