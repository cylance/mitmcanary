from time import sleep
import mitmcanary.detection.scheduling
from mitmcanary.detection.expected import ExpectedRequestManager, ExpectectedRequest
from mitmcanary.detection.results import ResultPropagator, ResultSubscriber
from mitmcanary.detection.alert import AlertManager
from mitmcanary.detection.interface import DetectionAPI

from plyer import notification


class NotificationResultSubscriber(ResultSubscriber):
    def __init__(self):
        ResultSubscriber.__init__(self)

    def on_result(self, (er, result)):
        if result["should_alert"]:
            notification.notify(**{
                'title': "Potential MITM Detected",
                'message': repr(result),
                'timeout': 60,
                'app_name': "MITM Canary"
            })
            print er, result


if __name__ == '__main__':
    # todo instantiate all the things?

    # start the results propagator
    # todo Maybe move most of this to something inside the detection subsystem to make it more portable
    ResultPropagator.i().add_subscriber("desktop_notifications", NotificationResultSubscriber())
    AlertManager.i().interface = DetectionAPI.i()
    ResultPropagator.i().start_propagator_thread()

    # load saved requests from disk
    ExpectedRequestManager.i().load_expected_requests()

    # load interface thread
    DetectionAPI.i().start_thread()

    # todo load scheduler thread
    # todo load interface thread (for gui connectivity)
    # todo wait for signal to shut things down
    # todo shut things down
    mitmcanary.detection.scheduling.Scheduler.i().main()
