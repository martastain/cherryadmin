from .context import CherryAdminContext

class CherryAdminView():
    def __init__(self, name, context, *args, **kwargs):
        self.name = name
        self.context = context

    def __getitem__(self, key):
        return self.context[key]

    def __setitem__(self, key, value):
        self.context["page"][key] = value

    def auth(self):
        return self["user"]

    def build(self, *args, **kwargs):
        self.context["page"].update(kwargs)

