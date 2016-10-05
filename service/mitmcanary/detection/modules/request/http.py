from mitmcanary.detection.request import RequestModule, RequestModuleManager

import urllib2
import cookielib
import random
from urlparse import urlparse
import base64
import socket
import gzip
from StringIO import StringIO
import traceback


class HTTPGetRequestModule(RequestModule):
    def get_name(self):
        return "HTTP Get Request"

    def __init__(self):
        self.proxies = None
        self.user_agent_pool = [
            "Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
            # "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",  # Lead to gzip failures
            "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        ]
        RequestModule.__init__(self)

    class RestrictiveHTTPRedirectHandler(urllib2.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            result = urllib2.HTTPError(req.get_full_url(), code, msg, headers, fp)
            result.status = code
            result.code = code
            return result

        http_error_301 = http_error_303 = http_error_307 = http_error_302

    @staticmethod
    def __open(self, fullurl, data=None, host_header=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        # accept a URL or a Request object
        if isinstance(fullurl, basestring):
            req = urllib2.Request(fullurl, data)
        else:
            req = fullurl
            if data is not None:
                req.add_data(data)

        if host_header is not None:
            req.add_header("Host", host_header)

        req.timeout = timeout
        protocol = req.get_type()

        # pre-process request
        meth_name = protocol + "_request"
        for processor in self.process_request.get(protocol, []):
            meth = getattr(processor, meth_name)
            req = meth(req)

        response = self._open(req, data)

        # post-process response
        meth_name = protocol + "_response"
        for processor in self.process_response.get(protocol, []):
            meth = getattr(processor, meth_name)
            response = meth(req, response)

        return response

    def make_request(self, request_arguments):
        url = request_arguments["url"]
        user_agent = None
        headers = None
        vhosts = None
        if "user_agent" in request_arguments and request_arguments["user_agent"] is not None:
            user_agent = request_arguments["user_agent"]

        if "headers" in request_arguments and request_arguments["headers"] is not None:
            headers = list(request_arguments["headers"])

        if "vhosts" in request_arguments and request_arguments["vhosts"] is not None:
            vhosts = request_arguments["vhosts"]

        results = {}
        try:
            cj = cookielib.CookieJar()
            if self.proxies is None:
                opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj),
                                              HTTPGetRequestModule.RestrictiveHTTPRedirectHandler)
            # else:
            #    proxy_handler = socksipyhandler.SocksiPyHandler(self.proxies[0], self.proxies[1], self.proxies[2])
            #    opener = urllib2.build_opener(proxy_handler, urllib2.HTTPCookieProcessor(cj),
            #                                  HTTPGetRequestModule.RestrictiveHTTPRedirectHandler)
            if user_agent is None:
                user_agent = random.choice(self.user_agent_pool)

            if headers is None:
                headers = []

            headers.append(("User-Agent", user_agent))

            opener.addheaders = headers

            if vhosts is not None:
                response = HTTPGetRequestModule.__open(opener, fullurl=url, host_header=random.choice(vhosts),
                                                       timeout=60)
            else:
                response = opener.open(fullurl=url, timeout=60)

            # This must be done before data is read from the connection
            results['ip'] = {
                "address": socket.gethostbyname(urlparse(url).hostname)
            }

            results['http'] = {
                "status_code": response.code,
                #"content": base64.b64encode(response.read()),
            }

            for k, v in response.headers.items():
                results['http']['headers-{0}'.format(k)] = v

            # Store the content for generic data file checks
            file_content = response.read()
            if 'headers-content-encoding' in results['http'] and "gzip" == results['http']['headers-content-encoding']:
                file_content = gzip.GzipFile(fileobj=StringIO(file_content)).read()

            results['file'] = {
                "content": base64.b64encode(file_content)
            }

            response.close()

            return results
        except:
            traceback.print_exc()
            return {
                "ip": {"address": None},
                "http": {
                    "status_code": None,
                    #"content": ""
                },
                "file": {"content": ""}
            }


RequestModuleManager.i().add_module(HTTPGetRequestModule())
