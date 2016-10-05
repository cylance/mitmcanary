from threading import RLock, Thread
from Queue import Queue


def _propagator_thread(result_propagator):
    while True:
        item = result_propagator.results.get()
        result_propagator._push_to_subscribers(item)
        result_propagator.results.task_done()


class ResultSubscriber:
    def __init__(self):
        pass

    def on_result(self, (expected_request, result)):
        raise NotImplementedError()


class ResultPropagator:
    _instance = None
    _instance_lock = RLock()

    def __init__(self):
        self._subscriber_lock = RLock()

        self.results = Queue()

        with self._subscriber_lock:
            self.subscribers = {}

    @staticmethod
    def instance():
        with ResultPropagator._instance_lock:
            if ResultPropagator._instance is None:
                ResultPropagator._instance = ResultPropagator()
            return ResultPropagator._instance

    @staticmethod
    def i():
        return ResultPropagator.instance()

    def add_subscriber(self, name, object):
        with self._subscriber_lock:
            self.subscribers[name] = object

    def add_result(self, expected_request, result):
        self.results.put((expected_request, result))

    def _push_to_subscribers(self, message):
        with self._subscriber_lock:
            for s, c in self.subscribers.items():
                c.on_result(message)

    def start_propagator_thread(self):
        t = Thread(target=_propagator_thread, args=(self,))
        t.daemon = True
        t.start()
