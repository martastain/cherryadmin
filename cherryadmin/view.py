class CherryAdminRawView(object):
    is_raw = True

    def __init__(self, name, context, *args, **kwargs):
        self.context = context
        self.view = name
        self.context["response"] = 200
        self["name"] = name
        self["mime"] = "text/html"
        self.response = 200
        self.body = ""

    @property
    def name(self):
        return self.context["page"]["name"]

    def __getitem__(self, key):
        return self.context[key]

    def __setitem__(self, key, value):
        self.context["page"][key] = value

    def auth(self):
        return self["user"]

    def build(self, *args, **kwargs):
        self.context["page"].update(kwargs)


class CherryAdminView(CherryAdminRawView):
    is_raw = False
