from mitmcanary.detection.analysis import AnalysisModule, AnalysisEngine


class StatusCodeAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "HTTP Status Code")

    def is_relevant(self, original_response):
        return "http" in original_response

    def __check_new_response__(self, original_response, new_response):
        # todo Check that the required category is present in both, not just one

        if original_response["http"]["status_code"] == new_response["http"]["status_code"]:
            return {"minimum_alarm": False, "text": "Status Codes Match"}
        else:
            return {"minimum_alarm": True,
                    "text": "Status codes do not match, expected {0}, recieved {1}".format(
                        original_response["http"]["status_code"], new_response["http"]["status_code"])}


class HTTPServerAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "HTTP Server Check")

    def is_relevant(self, original_response):
        return "http" in original_response and "headers-server" in original_response['http']

    def __check_new_response__(self, original_response, new_response):
        if "headers-server" in new_response['http']:
            if original_response['http']['headers-server'] == new_response['http']['headers-server']:
                return {
                    "minimum_alarm": False,
                    "text": "Servers are equal"
                }
            else:
                return {
                    "minimum_alarm": True,
                    "text": "Servers are not equal"
                }
        else:
            return {
                "minimum_alarm": True,
                "text": "Server header not specified"
            }


class HTTPContentExactCheckAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "HTTP Content Exact Check")

    def is_relevant(self, original_response):
        return "http" in original_response

    def __check_new_response__(self, original_response, new_response):
        if original_response['http']['content'] == new_response['http']['content']:
            return {
                "minimum_alarm": False, "text": "Content Match"
            }
        else:
            # todo Add deeper analysis of the non-matching response
            return {
                "minimum_alarm": True, "text": "Content does not Match"
            }


class HTTPIsContentEmpty(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "HTTP Empty Content Check")

    def is_relevant(self, original_response):
        return "http" in original_response

    def __check_new_response__(self, original_response, new_response):
        oe = len(original_response['http']['content']) == 0
        ne = len(new_response['http']['content']) == 0
        if oe == ne:
            return {
                "minimum_alarm": False, "text": "Empty Content Match"
            }
        else:
            # todo Add deeper analysis of the non-matching response
            return {
                "minimum_alarm": True, "text": "Empty Content does not Match"
            }


AnalysisEngine.i().add_analysis_modules(
    [
        StatusCodeAnalysisModule(),
        #HTTPContentExactCheckAnalysisModule(),
        HTTPServerAnalysisModule(),
        #HTTPIsContentEmpty(),
    ]
)
