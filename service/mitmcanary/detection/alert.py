from threading import RLock
from . import results, expected
import mitmcanary.persistence


class AlertManager(results.ResultSubscriber):
    _instance = None
    _instance_lock = RLock()

    def __init__(self):
        self._alert_lock = RLock()
        # Load alerts from disk
        with self._alert_lock:
            self.alerts = {}
            self.load_alerts()
        results.ResultPropagator.i().add_subscriber("AlertManager", self)
        results.ResultSubscriber.__init__(self)
        self.interface = None

    @staticmethod
    def instance():
        with AlertManager._instance_lock:
            if AlertManager._instance is None:
                AlertManager._instance = AlertManager()
            return AlertManager._instance

    @staticmethod
    def i():
        return AlertManager.instance()

    def on_result(self, (expected_request, result)):
        if result["should_alert"]:
            with self._alert_lock:
                self.alerts[result["uuid"]] = (expected_request, result)
            self.save_alerts()

            # Send alert to the interface
            self.interface.push_alerts(
                {
                    result["uuid"]: (expected_request, result)
                }
            )

    def save_alerts(self):
        with self._alert_lock:
            alerts = {}
            for n, m in self.alerts.items():
                alerts[n] = m
            mitmcanary.persistence.PersistenceManager.i().set_key_value("pending-alerts", alerts)

    def load_alerts(self):
        with self._alert_lock:
            self.alerts = {}
            try:
                serialized = mitmcanary.persistence.PersistenceManager.i().get_key_value("pending-alerts")
                for n, m in serialized.items():
                    self.alerts[n] = m
            except KeyError:
                # Nothing saved..
                pass

    def get_all_pending_alerts(self):
        alerts = {}
        with self._alert_lock:
            for identifier, alert in self.alerts.items():
                alerts[identifier] = alert
        return alerts

    def classify_result(self, uuid, is_malicious):

        with self._alert_lock:
            if uuid not in self.alerts:
                # Wtf...its not in here...
                # todo log this
                return False
            if not is_malicious:
                er, result = self.alerts[uuid]
                expected.ExpectedRequestManager.i().add_benign_result_to_expected_request(er, result["response"])
                # todo Reprocess other alerts
            del self.alerts[uuid]
            self.save_alerts()
