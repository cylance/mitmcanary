from . import analysis, request
import mitmcanary.detection.scheduling
import mitmcanary.persistence
import mitmcanary.detection.modules  # this has to stay
import json
from threading import RLock
from uuid import uuid4
import copy
import time


class ExpectedRequestManager:
    _instance = None
    _instance_lock = RLock()

    def __init__(self):
        self._module_lock = RLock()
        with self._module_lock:
            self.modules = {}

    @staticmethod
    def instance():
        with ExpectedRequestManager._instance_lock:
            if ExpectedRequestManager._instance is None:
                ExpectedRequestManager._instance = ExpectedRequestManager()
            return ExpectedRequestManager._instance

    @staticmethod
    def i():
        return ExpectedRequestManager.instance()

    def create_expected_request(self, request_module_name, request_configuration):
        er = ExpectectedRequest(request_module_name, request_configuration)
        # todo Find the best way to do this creation
        for _ in xrange(5):
            er.learn_from_request()
            time.sleep(60)

        self.add_expected_request(er)

    def add_expected_request(self, expected_request):
        with self._module_lock:
            self.modules[expected_request.identifier] = expected_request
            self.save_expected_requests()

    def add_benign_result_to_expected_request(self, er_uuid, result):
        with self._module_lock:
            if er_uuid in self.modules:
                self.modules[er_uuid].add_expected_response(result)
                self.modules[er_uuid].calculate_previous_analyses()
                self.save_expected_requests()
            else:
                # todo Log this error
                pass

    def get_expected_result_request_module_name(self, identifier):
        with self._module_lock:
            if identifier in self.modules:
                return self.modules[identifier].request_module_name
        return None

    def get_expected_result_request_module_configuration(self, identifier):
        with self._module_lock:
            if identifier in self.modules:
                return self.modules[identifier].request_configuration
        return None

    def save_expected_requests(self):
        with self._module_lock:
            modules = {}
            for n, m in self.modules.items():
                modules[n] = m.create_save_string()
            mitmcanary.persistence.PersistenceManager.i().set_key_value("expected-requests", modules)

    # Load ExpectedRequests from disk
    def load_expected_requests(self):
        with self._module_lock:
            self.modules = {}
            try:
                serialized = mitmcanary.persistence.PersistenceManager.i().get_key_value("expected-requests")
                for n, m in serialized.items():
                    self.modules[n] = ExpectectedRequest.load_from_save_string(m)
            except KeyError:
                # Nothing saved...
                pass


# Expected Request
class ExpectectedRequest:
    def __init__(self,
                 request_module_name=None,
                 request_configuration=None,
                 expected_responses=None,
                 identifier=None
                 ):
        # Everything gets this for now...
        self.schedule_strategy = mitmcanary.detection.scheduling.SimpleTimedScheduleStrategy()

        self.identifier = identifier if identifier is not None else "expected-request-{0}".format(str(uuid4()))
        self.request_module_name = request_module_name
        self.request_module = request.RequestModuleManager.i().get_by_name(request_module_name)
        self.request_configuration = request_configuration

        self.expected_responses_lock = RLock()
        with self.expected_responses_lock:
            if expected_responses is None:
                self.expected_responses = []
            else:
                self.expected_responses = expected_responses

        self.analyses_engine = analysis.AnalysisEngine.i()

        self.previous_analyses_lock = RLock()
        with self.previous_analyses_lock:
            self.previous_analyses = []

        self.calculate_previous_analyses()

    def create_save_string(self):
        with self.expected_responses_lock:
            with self.previous_analyses_lock:
                save_state = {
                    "request_module_name": self.request_module_name,
                    "request_configuration": self.request_configuration,
                    "expected_responses": self.expected_responses,
                    "identifier": self.identifier
                }
        return json.dumps(save_state)

    @staticmethod
    def load_from_save_string(save_string):
        save_state = json.loads(save_string)
        return ExpectectedRequest(
            request_module_name=save_state["request_module_name"],
            request_configuration=save_state["request_configuration"],
            expected_responses=save_state["expected_responses"],
            identifier=save_state["identifier"]
        )

    def calculate_previous_analyses(self):
        with self.expected_responses_lock:
            with self.previous_analyses_lock:
                self.previous_analyses = []
                for x in self.expected_responses:
                    for y in self.expected_responses:
                        #ia, ian = self.diff_responses(x, y)
                        #if ia is not None or ian is not None:
                        analysis = self.check_all_modules(x, y)
                        if self.is_analysis_unique(analysis):
                            self.previous_analyses.append(self.check_all_modules(x, y))

    def set_request_module(self, request_module):
        self.request_module = request_module

    def set_request_configuration(self, configuration):
        self.request_configuration = configuration

    def make_request(self):
        return self.request_module.make_request(copy.deepcopy(self.request_configuration))

    def check_all_modules(self, original_response, new_response):
        return self.analyses_engine.check_all_modules(original_response, new_response)

    def is_analysis_unique(self, analysis, analyses=None):
        with self.previous_analyses_lock:
            to_check = list(self.previous_analyses)
            if analyses is not None:
                to_check = analyses

            for a in to_check:
                io, ion = self.diff_analysis(a, analysis)
                if io is None and ion is None:
                    return False
        return True

    def learn_from_request(self):
        response = self.make_request()

        # Check for redundant responses
        is_redundant = False
        with self.expected_responses_lock:
            for r in self.expected_responses:
                in_o, in_n = self.diff_responses(r, response)
                if in_o is None and in_n is None:
                    is_redundant = True
                    break

        if not is_redundant:
            self.add_expected_response(response)

        self.calculate_previous_analyses()

        return response

    def add_expected_response(self, response):
        with self.expected_responses_lock:
            self.expected_responses.append(response)

    def diff_dicts(self, original_response, new_response):
        in_original = {}
        in_new = {}
        for key in set(original_response.keys() + new_response.keys()):
            if key not in original_response:
                in_new[key] = new_response[key]
                continue
            if key not in new_response:
                in_original[key] = original_response[key]
                continue

            non_shared = set(original_response[key].items()) ^ set(new_response[key].items())
            if len(non_shared) > 0:
                io = non_shared & set(original_response[key].items())
                if len(io) > 0:
                    in_original[key] = list(io)

                ion = non_shared & set(new_response[key].items())
                if len(ion) > 0:
                    in_new[key] = list(ion)

        return in_original if len(in_original.keys()) > 0 else None, in_new if len(in_new.keys()) > 0 else None

    def diff_responses(self, original_response, new_response):
        return self.diff_dicts(original_response, new_response)

    def diff_analysis(self, original_analysis, new_analysis):
        return self.diff_dicts(original_analysis, new_analysis)

    def compare_against_all_responses(self, new_response):
        with self.expected_responses_lock:
            analyses = []
            for response in self.expected_responses:
                analysis = self.check_all_modules(response, new_response)
                if self.is_analysis_unique(analysis, analyses=analyses):
                    analyses.append(analysis)
        return analyses

    def run_check(self):
        new_response = self.make_request()
        analyses = self.compare_against_all_responses(new_response)
        matches = []
        for a in analyses:
            analysis_comparision = self.is_analysis_unique(a)
            if analysis_comparision:
                matches.append(a)
        return len(matches) > 0, matches, new_response
