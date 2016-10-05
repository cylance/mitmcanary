import mitmcanary.detection.scheduling
from mitmcanary.detection.expected import ExpectedRequestManager, ExpectectedRequest
from multiprocessing.pool import ThreadPool
import time
import itertools


def learn_a_thing(er):
    try:
        ExpectedRequestManager.i().create_expected_request(er[0], er[1])
    except:
        import traceback
        print er
        traceback.print_exc()


if __name__ == '__main__':
    ers = [
        ("HTTP Get Request", {"url": "http://defense.ballastsecurity.net/static/login.html",
                                                    "headers": [("Accept-Encoding", "gzip")]}),
        ("HTTP Get Request", {"url": "http://defense.ballastsecurity.net/static/login.html"}),
        ("HTTP Get Request", {"url": "http://www.facebook.com/"}),
        ("MDNS A Request", {"domain": "bwall.github.io"}),
        ("DNS A Request", {"domain": "bwall.github.io"}),
        ("DNS A Request", {"domain": "google.com"}),
        ("MDNS A Request", {"domain": "WPAD"}),
        ("MDNS A Request", {"domain": "ISATAP"}),
        ("MDNS A Request", {"domain": "corppki"}),
        ("SSL Request", {"remote_host": "www.cylance.com", "remote_port": 443}),
    ]

    pool = ThreadPool(processes=16)

    for _ in pool.imap(learn_a_thing, ers):
        pass

