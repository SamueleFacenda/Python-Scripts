from threading import Event, Lock
import os
import pickle
import atexit
import functools
import time

class Cache():
    def __init__(self, name):
        self.path = os.path.join(os.environ.get('XDG_CACHE_HOME', os.path.expanduser('~/.cache')), 'tt')
        os.makedirs(self.path, exist_ok=True)
        self.path = os.path.join(self.path, name)

        if os.path.exists(self.path):
            last_modified = os.path.getmtime(self.path)
        else:
            last_modified = 0

        ONE_WEEK = 60*60*24*7
        if time.time() - last_modified < ONE_WEEK:
            self.cache = pickle.load(open(self.path, 'rb'))
            assert isinstance(self.cache, dict)
        else:
            self.cache: dict[str, object] = {}
        
        self.is_dirty: Event = Event()
        self.lock: Lock = Lock()

        atexit.register(self.dump)

    def __getitem__(self, key):
        with self.lock:
            return self.cache[key]

    def __setitem__(self, key, value):
        with self.lock:
            self.cache[key] = value
            self.is_dirty.set()

    def __contains__(self, key):
        with self.lock:
            return key in self.cache

    def dump(self):
        if self.is_dirty.is_set():
            with self.lock:
                pickle.dump(self.cache, open(self.path, 'wb'))
                self.is_dirty.clear()

class cached:
    '''
    Decorator to cache the results of a function call.
    The cache is persistent, i.e. it is saved to disk and loaded from disk.
    '''

    def __init__(self, func):
        self.func = func
        self.cache = Cache(func.__name__)

    def args_to_kwargs(self, args):
        return dict(zip(self.func.__code__.co_varnames, args))

    def _get_key(self, args, kwargs):
        return str({**self.args_to_kwargs(args), **kwargs})

    def __call__(self, *args, **kwargs):
            key = self._get_key(args, kwargs)
            if key in self.cache:
                return self.cache[key]
            else:
                result = self.func(*args, **kwargs)
                self.cache[key] = result
                return result

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)