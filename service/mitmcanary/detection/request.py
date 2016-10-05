from threading import RLock


class RequestModuleManager:

    _instance = None
    _instance_lock = RLock()

    def __init__(self):
        self.modules = {}

    @staticmethod
    def instance():
        with RequestModuleManager._instance_lock:
            if RequestModuleManager._instance is None:
                RequestModuleManager._instance = RequestModuleManager()
            return RequestModuleManager._instance

    @staticmethod
    def i():
        return RequestModuleManager.instance()

    def add_module(self, module):
        self.modules[module.get_name()] = module

    def get_by_name(self, name):
        return self.modules[name]


class RequestModule:
    def __init__(self):
        pass

    def get_name(self):
        raise NotImplementedError()

    def make_request(self, request_arguments):
        raise NotImplementedError()

