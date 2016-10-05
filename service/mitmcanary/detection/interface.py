from kivy.lib import osc
from time import sleep, asctime, localtime
import json
import threading
from threading import RLock
from . import alert, expected
import datetime


ACTIVITY_PORT = 3001
SERVICE_PORT = 3000
API_OFFSET = "/mitmcanary/"


class DetectionAPI:
    _instance = None
    _instance_lock = RLock()

    @staticmethod
    def instance():
        with DetectionAPI._instance_lock:
            if DetectionAPI._instance is None:
                DetectionAPI._instance = DetectionAPI()
            return DetectionAPI._instance

    @staticmethod
    def i():
        return DetectionAPI.instance()

    def __init__(self):
        osc.init()
        self.oscid = osc.listen(ipAddr='127.0.0.1', port=SERVICE_PORT)
        osc.bind(self.oscid, self.handle_incoming_message, API_OFFSET)
        osc.bind(self.oscid, self.handle_request_for_pending_alerts, API_OFFSET + "pending-alerts")
        osc.bind(self.oscid, self.handle_classify_alert, API_OFFSET + "classify-alert")

    def handle_incoming_message(self, message, *args):
        print "Message received: {0}".format(message)
        osc.sendMsg(API_OFFSET, [asctime(localtime()), ], port=ACTIVITY_PORT)

    def handle_request_for_pending_alerts(self, message, *args):
        self.provide_pending_alerts()

    def provide_pending_alerts(self):
        alerts = alert.AlertManager.i().get_all_pending_alerts()
        self.push_alerts(alerts)

    def handle_classify_alert(self, message, *args):
        print "Classifying alert", message
        m = json.loads(message[2])
        alert.AlertManager.i().classify_result(m['id'], "malicious" in m)

    def push_alerts(self, alerts):
        message = {
            "alerts": {}
        }
        for i, a in alerts.items():
            message["alerts"][i] = {
                "expected_request_id": a[0],
                "expected_request_name": expected.ExpectedRequestManager.i().get_expected_result_request_module_name(a[0]),
                "timestamp": datetime.datetime.fromtimestamp(int(a[1]["timestamp"])).strftime('%Y-%m-%d %H:%M:%S'),
                "response": a[1]["response"],
                "unique_analyses": a[1]["unique_analyses"],
                "expected_request_configuration": expected.ExpectedRequestManager.i().get_expected_result_request_module_configuration(a[0]),
            }

        osc.sendMsg(
            API_OFFSET + "pending-alerts",
            [json.dumps(message), ],
            port=ACTIVITY_PORT
        )

    def start_thread(self):
        t = threading.Thread(target=self.run)
        t.daemon = True
        t.start()

    def run(self):
        while True:
            osc.readQueue(self.oscid)
            sleep(0.1)


if __name__ == "__main__":
    dapi = DetectionAPI()
    dapi.run()

