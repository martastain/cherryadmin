#!/usr/bin/env python

from cherryadmin import *


def login_helper(login, password):
    if login == password == "demo":
        return {
                "login" : "demo",
                "role" : "admin",
                "first_name" : "Nikola",
                "last_name" : "Sanders",
            }
    return False


def site_context_helper():
    return {
            "name" : "CherryAdmin"
        }


def page_context_helper():
    return {
            "name" : "Le page"
        }


admin = CherryAdmin(
        static_dir="site/static",
        templates_dir="site/templates",
        login_helper=login_helper,
        site_context_helper=site_context_helper,
        page_context_helper=page_context_helper,
        blocking=True,
    )

