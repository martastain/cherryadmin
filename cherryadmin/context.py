class CherryAdminContext(dict):
    def message(self, message, level="info"):
        if not "messages" in self.keys():
            self["messages"] = []
        self["messages"].append([message, level])
