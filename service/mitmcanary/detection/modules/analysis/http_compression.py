from mitmcanary.detection.analysis import AnalysisModule, AnalysisEngine
import gzip
import base64
from StringIO import StringIO


class HTTPCompressionCheckAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "HTTP Compression Check")

    def is_relevant(self, original_response):
        return "http" in original_response

    def __check_new_response__(self, original_response, new_response):
        if "headers-content-encoding" in original_response['http']:
            if 'headers-content-encoding' in new_response['http'] and \
                            original_response['http']['headers-content-encoding'] == new_response['http']['headers-content-encoding']:
                # todo Identify if compressed or not
                return {
                    "minimum_alarm": False,
                    "text": "Compression status match (enabled)"
                }

            else:
                # todo Identify if original is compressed
                return {
                    "minimum_alarm": True,
                    "text": "Content encodings are not equal"
                }

        elif "headers-content-encoding" in new_response['http']:
            # its in the new, not in the old
            return {
                "minimum_alarm": True,
                "text": "Unexpected content encoding"
            }
        else:
            # neither have content encoding specified
            return {
                "minimum_alarm": False,
                "text": "Compression status match (disabled)"
            }


class HTTPCompressedContentMatchAnalysisModule(AnalysisModule):
    def __init__(self):
        AnalysisModule.__init__(self, "HTTP Compressed Content Match")

    def is_relevant(self, original_response):
        return "http" in original_response and \
               'headers-content-encoding' in original_response['http'] and \
               "gzip" == original_response['http']['headers-content-encoding']

    def __check_new_response__(self, original_response, new_response):
        # is the new response even compressed?
        if 'http' not in new_response:
            return {
                "minimim_alarm": True,
                "text": "Response is not recognized as HTTP"
            }

        if 'headers-content-encoding' not in new_response['http']:
            return {
                "minimum_alarm": True,
                "text": "No Content-Encoding header specified"
            }

        if 'gzip' != new_response['http']['headers-content-encoding']:
            return {
                "minimum_alarm": True,
                "text": "Gzip is not specified Content-Encoding"
            }

        # Decompress original
        original_file = gzip.GzipFile(fileobj=StringIO(base64.b64decode(original_response['http']['content']))).read()
        new_file = gzip.GzipFile(fileobj=StringIO(base64.b64decode(new_response['http']['content']))).read()

        if original_file == new_file:
            return {
                "minimum_alarm": False,
                "text": "Compressed contents are equal"
            }
        else:
            return {
                "minimum_alarm": True,
                "text": "Compressed contents are not equal"
            }


AnalysisEngine.i().add_analysis_modules(
    [
        #HTTPCompressedContentMatchAnalysisModule(),
        HTTPCompressionCheckAnalysisModule(),
    ]
)
