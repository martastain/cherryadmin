class CherryAdminView(object):
    def __init__(self, name, context, *args, **kwargs):
        self.context = context
        self.view = name
        self.context["page"]["name"] = name
        self.context["response"] = 200

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

