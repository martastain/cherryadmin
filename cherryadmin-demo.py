#!/usr/bin/env python3

from cherryadmin import CherryAdmin


def login_helper(login, password):
    if login == password == "admin":
        return {
            "login": "admin",
            "role": "admin",
            "first_name": "Admin",
            "last_name": "Adminowich",
        }
    return False


def site_context_helper():
    return {
        "name": "CherryAdmin"
    }


def page_context_helper():
    return {
        "name": "Cherryadmin"
    }


admin = CherryAdmin(
    host="0.0.0.0",
    port=8822,
    static_dir="site/static",
    templates_dir="site/templates",
    login_helper=login_helper,
    site_context_helper=site_context_helper,
    page_context_helper=page_context_helper,
    blocking=True,
)
