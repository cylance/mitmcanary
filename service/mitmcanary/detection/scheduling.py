import mitmcanary.detection.expected
import mitmcanary.detection.results

from threading import RLock, Thread
import time
from uuid import uuid4


def _launch_check_async(expected_request):
    #print "Checking {0}:{1}".format(expected_request.request_module_name, expected_request.request_configuration)
    result = expected_request.run_check()
    #print "Done {0}:{1}".format(expected_request.request_module_name, expected_request.request_configuration)
    result_object = {
        "should_alert": result[0],
        "unique_analyses": result[1],
        "response": result[2],
        "timestamp": float(time.time()),
        "uuid": "result-{0}".format(str(uuid4()))
    }
    mitmcanary.detection.results.ResultPropagator.i().add_result(expected_request.identifier, result_object)


class Scheduler:
    _instance = None
    _instance_lock = RLock()

    def __init__(self):
        self.modules = {}
        self._check_lock = RLock()

    @staticmethod
    def instance():
        with Scheduler._instance_lock:
            if Scheduler._instance is None:
                Scheduler._instance = Scheduler()
            return Scheduler._instance

    @staticmethod
    def i():
        return Scheduler.instance()

    def launch_check(self, expected_request):
        thread = Thread(
            target=_launch_check_async,
            args=(expected_request,),
        )
        thread.daemon = True
        thread.start()

    def run_schedule_check(self):
        minimum_wait = 60 * 30
        with self._check_lock:
            for name, er in mitmcanary.detection.expected.ExpectedRequestManager.i().modules.items():
                t = er.schedule_strategy.get_next_run_time()
                if t == 0:
                    er.schedule_strategy.report_run()
                    self.launch_check(er)
                    t = er.schedule_strategy.get_next_run_time()

                # Set the minimum_wait time to the lowest
                minimum_wait = min(minimum_wait, t)
        return minimum_wait

    def main(self):

        # todo implement safe shutdown mechanism
        while True:
            minimum_wait = self.run_schedule_check()

            print "Sleeping for {0} seconds".format(minimum_wait)
            time.sleep(minimum_wait)


class ScheduleStrategy:

    def __init__(self):
        pass

    def push_event(self, event_data):
        """
        When a strategy requests access to a certain event, it gets sent information
        when that event fires off
        :param event_data:
        :return:
        """
        raise NotImplementedError()

    def get_next_run_time(self):
        """
        Each schedule strategy manages its own state to determine if it should
        run now, and the scheduler checks this function to see how long until
        it should run next (will only run when 0 is returned)
        :return: Seconds until next run
        """
        raise NotImplementedError()

    def get_event_subscriptions(self):
        raise NotImplementedError()

    def report_run(self):
        raise NotImplementedError()

    
class SimpleTimedScheduleStrategy(ScheduleStrategy):
    """
    Runs every 10 minutes
    """

    def __init__(self):
        self.last_run = 0
        # todo Change back from 1 minute
        self.seconds_between_runs = 60 * 1
        ScheduleStrategy.__init__(self)

    def push_event(self, event_data):
        pass

    def get_event_subscriptions(self):
        return []

    def report_run(self):
        self.last_run = int(time.time())

    def get_next_run_time(self):
        t = self.seconds_between_runs - (int(time.time()) - self.last_run)
        if t < 0:
            t = 0
        return t

