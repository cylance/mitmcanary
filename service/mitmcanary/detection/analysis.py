from threading import RLock


class AnalysisEngine:
    _instance = None
    _instance_lock = RLock()

    def __init__(self):
        self.modules = []

    @staticmethod
    def instance():
        with AnalysisEngine._instance_lock:
            if AnalysisEngine._instance is None:
                AnalysisEngine._instance = AnalysisEngine()
            return AnalysisEngine._instance

    @staticmethod
    def i():
        return AnalysisEngine.instance()

    def add_analysis_module(self, module):
        duplicate = False
        for m in self.modules:
            if m.get_name() == module.get_name():
                duplicate = True
                break
        if not duplicate:
            self.modules.append(module)

    def add_analysis_modules(self, modules):
        for module in modules:
            self.add_analysis_module(module)

    def check_all_modules(self, original_response, new_response):
        results = {}
        for module in self.modules:
            name = module.get_name()
            if module.is_relevant(original_response):
                results[name] = module.check_new_response(original_response, new_response)
        return results


# Analysis Module Start
class AnalysisModule:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def is_relevant(self, original_response):
        raise NotImplementedError()

    def check_new_response(self, original_response, new_response):
        if self.is_relevant(original_response):
            r = self.__check_new_response__(original_response, new_response)
            r["relevant"] = True
            return r
        else:
            return {"relevant": False}

    def __check_new_response__(self, original_response, new_response):
        raise NotImplementedError()
