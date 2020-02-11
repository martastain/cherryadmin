__all__ = ["CherryAdmin", "CherryAdminView", "CherryAdminRawView"]

import os
import cherrypy

from nxtools import *

from .handler import CherryAdminHandler
from .context import CherryAdminContext
from .sessions import CherryAdminSessions
from .view import CherryAdminView, CherryAdminRawView


script_name =  os.path.basename(os.path.splitext(__file__)[0])

def default_context_helper():
    return {}

def default_user_context_helper(data):
    return data


default_settings = {

        #
        # Environment
        #

        "templates_dir" : "templates",
        "static_dir" : "static",
        "sessions_dir" : "/tmp/" + script_name + "_sessions",
        "sessions_timeout" : 60*24*7,
        "minify_html" : True,
        "log_screen" : False,

        #
        # Server configuration
        #

        "host" : "0.0.0.0",
        "port" : 8080,
        "blocking" : False,

        #
        # Application
        #

        "views" : {"index" : CherryAdminView},
        "api_methods" : {},
        "login_helper" : lambda x, y: False,
        "site_context_helper" : default_context_helper,
        "page_context_helper" : default_context_helper,
        "user_context_helper" : default_user_context_helper,
    }



class CherryAdmin():
    def __init__(self, **kwargs):
        self.settings = default_settings
        self.settings.update(kwargs)

        self.is_running = False
        self.handler = CherryAdminHandler(self)
        self.sessions = CherryAdminSessions(
                    self.settings.get("sessions_dir", "/tmp/sessions"),
                    self.settings.get("sessions_timeout", 3600*24*30),
                    self.settings.get("hash_salt", "iamverysaltysalt")
                )

        if not os.path.exists(self["sessions_dir"]):
            os.makedirs(self["sessions_dir"])

        static_root, static_dir = os.path.split(os.path.abspath(self["static_dir"]))

        self.config = {
            '/': {
                'tools.proxy.on': True,
                'tools.proxy.local': 'X-Forwarded-Host',
                'tools.proxy.local': 'Host',
                'tools.staticdir.root': static_root,
                'tools.trailing_slash.on' : False,
                'error_page.default': self.handler.cherrypy_error,
                },

            '/static': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': static_dir
                },

           '/favicon.ico': {
                'tools.staticfile.on': True,
                'tools.staticfile.filename': os.path.join(static_root, static_dir, "img", "favicon.ico")
                },
            }

        cherrypy.config.update({
            "server.socket_host" : str(self["host"]),
            "server.socket_port" : int(self["port"]),
            "log.screen" : self["log_screen"]
            })


        cherrypy.tree.mount(self.handler, "/", self.config)
        cherrypy.engine.subscribe('start', self.start)
        cherrypy.engine.subscribe('stop', self.stop)
        cherrypy.engine.start()
        logging.goodnews("Web service started")
        if self["blocking"]:
            cherrypy.engine.block()


    def __getitem__(self, key):
        return self.settings[key]

    def start(self):
        self.is_running = True

    def stop(self):
        logging.warning("Web service stopped")
        self.is_running = False

    def shutdown(self):
        cherrypy.engine.exit()
