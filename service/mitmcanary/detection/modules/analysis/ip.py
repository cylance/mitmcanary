from mitmcanary.detection.analysis import AnalysisModule, AnalysisEngine


class IPIsPrivateAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "IP Is Private")

    def is_relevant(self, original_response):
        return "ip" in original_response and 'address' in original_response['ip'] and original_response['ip']['address'] is not None

    def is_local(self, ip):
        if ip is None:
            return False
        return ip.startswith("10.") or \
               ip.startswith("172.16.") or \
               ip.startswith("192.168.") or \
               ip.startswith("fd") or \
               ip.startswith("169.254.") or \
               ip.startswith("fc") or \
               ip.startswith('fe8') or \
               ip.startswith("127.")

    def __check_new_response__(self, original_response, new_response):
        original_local = self.is_local(original_response['ip']['address'])
        new_local = self.is_local(new_response['ip']['address'])

        if original_local == new_local:
            return {
                "minimum_alarm": False,
                "text": "IP Network Localities Match"
            }
        elif original_local:
            return {
                "minimum_alarm": True,
                "text": "Expected Local IP, received External IP"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "Expected External IP, received Local IP"
            }


class IPExactMatchAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "IP Exact Match")

    def is_relevant(self, original_response):
        return "ip" in original_response

    def __check_new_response__(self, original_response, new_response):
        if original_response['ip']['address'] == new_response['ip']['address']:
            return {
                "minimum_alarm": False,
                "text": "IP addresses are an exact match"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "IP addresses do not match"
            }


class IPExistsAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "IP Exists Match")

    def is_relevant(self, original_response):
        return "ip" in original_response

    def __check_new_response__(self, original_response, new_response):
        oe = original_response['ip']['address'] is None
        ne = new_response['ip']['address'] is None
        if oe == ne:
            return {
                "minimum_alarm": False,
                "text": "IP existence matches"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "IP existence does not match"
            }


class IPClassAMatchModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "IP Class A Match")

    def is_relevant(self, original_response):
        return "ip" in original_response and "address" in original_response['ip'] and original_response['ip']['address'] is not None and "." in original_response['ip']['address']

    @staticmethod
    def get_class_a(response):
        if "ip" in response:
            if "address" in response["ip"]:
                if response["ip"]["address"] is not None:
                    if "." in response["ip"]["address"]:
                        return response["ip"]["address"].split(".")[0]
        return None

    def __check_new_response__(self, original_response, new_response):
        oe = IPClassAMatchModule.get_class_a(original_response)
        ne = IPClassAMatchModule.get_class_a(new_response)

        if oe == ne:
            return {
                "minimum_alarm": False,
                "text": "IP class A matches"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "IP class A mismatch"
            }


class IPClassBMatchModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "IP Class B Match")

    def is_relevant(self, original_response):
        return "ip" in original_response and "address" in original_response['ip'] and original_response['ip']['address'] is not None and "." in original_response['ip']['address']

    @staticmethod
    def get_class_b(response):
        if "ip" in response:
            if "address" in response["ip"]:
                if response["ip"]["address"] is not None:
                    if "." in response["ip"]["address"]:
                        return ".".join(response["ip"]["address"].split(".")[0:2])
        return None

    def __check_new_response__(self, original_response, new_response):
        oe = IPClassBMatchModule.get_class_b(original_response)
        ne = IPClassBMatchModule.get_class_b(new_response)

        if oe == ne:
            return {
                "minimum_alarm": False,
                "text": "IP class B matches"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "IP class B mismatch"
            }


class IPClassCMatchModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "IP Class C Match")

    def is_relevant(self, original_response):
        return "ip" in original_response and "address" in original_response['ip'] and original_response['ip']['address'] is not None and "." in original_response['ip']['address']

    @staticmethod
    def get_class_c(response):
        if "ip" in response:
            if "address" in response["ip"]:
                if response["ip"]["address"] is not None:
                    if "." in response["ip"]["address"]:
                        return ".".join(response["ip"]["address"].split(".")[0:3])
        return None

    def __check_new_response__(self, original_response, new_response):
        oe = IPClassCMatchModule.get_class_c(original_response)
        ne = IPClassCMatchModule.get_class_c(new_response)

        if oe == ne:
            return {
                "minimum_alarm": False,
                "text": "IP class C matches"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "IP class C mismatch"
            }


AnalysisEngine.i().add_analysis_modules(
    [
        IPIsPrivateAnalysisModule(),
        IPExactMatchAnalysisModule(),
        IPExistsAnalysisModule(),
        IPClassAMatchModule(),
        IPClassBMatchModule(),
        IPClassCMatchModule(),
    ]
)