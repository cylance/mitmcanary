"""
Centralized disk access to save on the headache of working on so many different operating systems
"""
# https://kivy.org/docs/api-kivy.storage.html#module-kivy.storage
import json
from kivy.storage.jsonstore import JsonStore
from threading import RLock


class PersistenceManager:
    _instance = None
    _instance_lock = RLock()

    def __init__(self):
        self._access_lock = RLock()
        self.modules = {}

        with self._access_lock:
            self.store = JsonStore('persist.json')

    @staticmethod
    def instance():
        with PersistenceManager._instance_lock:
            if PersistenceManager._instance is None:
                PersistenceManager._instance = PersistenceManager()
            return PersistenceManager._instance

    @staticmethod
    def i():
        return PersistenceManager.instance()

    def set_key_value(self, key, v):
        v = json.dumps(v)
        with self._access_lock:
            self.store.put(key, val=v)

    def get_key_value(self, key):
        with self._access_lock:
            return json.loads(self.store.get(key)['val'])
