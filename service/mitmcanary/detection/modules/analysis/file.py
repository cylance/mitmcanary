from mitmcanary.detection.analysis import AnalysisModule, AnalysisEngine

import base64


class FileExactMatchModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "File Exact Match")

    def is_relevant(self, original_response):
        return "file" in original_response and "content" in original_response["file"]

    def __check_new_response__(self, original_response, new_response):
        # no need to decode for an exact match check
        if original_response["file"]["content"] == new_response["file"]["content"]:
            return {"minimum_alarm": False, "text": "Files match exactly"}
        else:
            return {"minimum_alarm": True,
                    "text": "Files are not an exact match"}


class FileIsTruncated(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "File Is Truncated")

    def is_relevant(self, original_response):
        return "file" in original_response and "content" in original_response["file"]

    def __check_new_response__(self, original_response, new_response):
        if base64.b64decode(original_response["file"]["content"]).startswith(base64.b64decode(new_response["file"]["content"])):
            return {"minimum_alarm": False, "text": "File is truncated or match"}
        else:
            return {"minimum_alarm": True,
                    "text": "File is not truncated"}


class FileIsExtended(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "File Is Extended")

    def is_relevant(self, original_response):
        return "file" in original_response and "content" in original_response["file"]

    def __check_new_response__(self, original_response, new_response):
        if base64.b64decode(new_response["file"]["content"]).startswith(base64.b64decode(original_response["file"]["content"])):
            return {"minimum_alarm": False, "text": "File is extended or match"}
        else:
            return {"minimum_alarm": True,
                    "text": "File is not an extension of the original"}


class FileSameFourBytes(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "File Same Four Bytes")

    def is_relevant(self, original_response):
        return "file" in original_response and "content" in original_response["file"]

    def __check_new_response__(self, original_response, new_response):
        if base64.b64decode(new_response["file"]["content"])[:4] == base64.b64decode(original_response["file"]["content"])[:4]:
            return {"minimum_alarm": False, "text": "File First four bytes match"}
        else:
            return {"minimum_alarm": True,
                    "text": "File First four bytes do not match"}


AnalysisEngine.i().add_analysis_modules(
    [
        FileExactMatchModule(),
        FileIsTruncated(),
        FileIsExtended(),
    ]
)
