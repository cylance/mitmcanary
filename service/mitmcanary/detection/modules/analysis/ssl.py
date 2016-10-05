from mitmcanary.detection.analysis import AnalysisModule, AnalysisEngine

import json


class SSLChainExactMatch(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "SSL Certificate Chain Exact Match")

    def is_relevant(self, original_response):
        return "ssl" in original_response and "chain" in original_response["ssl"]

    def __check_new_response__(self, original_response, new_response):
        oe = original_response["ssl"]["chain"]
        ne = ""
        if "ssl" in new_response:
            if "chain" in new_response["ssl"]:
                ne = new_response["ssl"]["chain"]

        if oe == ne:
            return {
                "minimum_alarm": False,
                "text": "SSL Certificate chain exact match"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "SSL Certificate chain mismatch"
            }


class SSLChainFirstExactMatch(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "SSL Certificate First in Chain Exact Match")

    def is_relevant(self, original_response):
        return "ssl" in original_response and "chain" in original_response["ssl"]

    def __check_new_response__(self, original_response, new_response):
        oe = json.loads(original_response["ssl"]["chain"])[0]
        ne = ""
        if "ssl" in new_response:
            if "chain" in new_response["ssl"]:
                ne = json.loads(new_response["ssl"]["chain"])[0]

        if oe == ne:
            return {
                "minimum_alarm": False,
                "text": "SSL First Certificate chain exact match"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "SSL First Certificate chain mismatch"
            }


class SSLChainLastExactMatch(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "SSL Certificate Last in Chain Exact Match")

    def is_relevant(self, original_response):
        return "ssl" in original_response and "chain" in original_response["ssl"]

    def __check_new_response__(self, original_response, new_response):
        oe = json.loads(original_response["ssl"]["chain"])[-1]
        ne = ""
        if "ssl" in new_response:
            if "chain" in new_response["ssl"]:
                ne = new_response["ssl"]["chain"][-1]

        if oe == ne:
            return {
                "minimum_alarm": False,
                "text": "SSL Last Certificate chain exact match"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "SSL Last Certificate chain mismatch"
            }


AnalysisEngine.i().add_analysis_modules(
    [
        SSLChainExactMatch(),
        SSLChainFirstExactMatch(),
        SSLChainLastExactMatch(),
    ]
)
