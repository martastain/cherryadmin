import os
import json

import cherrypy
import jinja2

api_headers = [
        ["Content-Type", "application/json"],
        ["Connection", "keep-alive"],
        ["Cache-Control", "no-cache"],
        ["Access-Control-Allow-Origin", "*"]
    ]

class Context(dict):
    def message(self, message, level="info"):
        if not messages in self.keys():
            self["flash_messages"] = []
        self["flash_messages"].append([message, level])


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
        context = Context()
        context.update({
                "user" : user_data,
                "site" : self.parent["site_context_helper"](),
                "page" : self.parent["page_context_helper"](),
            })
        return context


    def render(self, view, **context):
        template = self.jinja.get_template("{}.html".format(view))
        context["view"] = view
        #TODO
        #js_path = os.path.join(config["nebula_root"], "hub", "static", "js", "{}.js".format(view))
        #if os.path.exists(js_path):
        #    context["view_js"] = "/static/js/{}.js".format(view)
        return template.render(**context)


    def render_error(self, response_code, message):
        cherrypy.response.status = response_code
        return self.render("error", {"error_messsage" : message, "error_code" : response_code })

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
        try:
            view_name = args[0]
            if not view_name in self.parent["views"]:
                raise IndexError
        except IndexError:
            view_name = "index"

        context = self.context()
        if not context["user"]:
            return self.render("login", **context)

        if args:
            args = args[1:]

        view = self.parent["views"][view_name]
        context = view(context, args, **kwargs)
        return self.render(view_name, **context)




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
