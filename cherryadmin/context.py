class CherryAdminContext(dict):
    def message(self, message, level="info"):
        if "messages" not in self.keys():
            self["messages"] = []
        self["messages"].append([message, level])
