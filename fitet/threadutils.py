from multiprocessing.pool import ThreadPool
from threading import Event, Lock
import logging

class RunnerCounter:
    def __init__(self, count=0):
        self.count = count
        self.count_lock = Lock()
        self.no_one_running = Event()
        if count <= 0:
            self.no_one_running.set()

    def add(self, n=1):
        with self.count_lock:
            self.count += n
            if self.count > 0:
                self.no_one_running.clear()

    def sub(self, n=1):
        with self.count_lock:
            self.count -= n
            if self.count <= 0:
                self.no_one_running.set()

    def wait_for_zero(self):
        self.no_one_running.wait()

    def wrap(self, fn, add=True):
        def wrapped(*args, **kwargs):
            if add:
                self.add()
            try:
                out = fn(*args, **kwargs)
            except:
                self.sub()
                logging.exception("Error in wrapped function")
            self.sub()
            return out
        return wrapped

    def required(self, fn):
        return self.wrap(fn, add=False)

class WaitableThreadPool(ThreadPool):
    def error_callback(applyResultSelf, error):
        try:
            raise error
        except:
            # python :(
            logging.exception("Error in thread")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = RunnerCounter()

    def map_async(self, fn, iterable, callback=None):
        self.counter.add(len(iterable))
        return super().map_async(self.counter.required(fn), iterable, callback, error_callback=self.error_callback)

    def starmap_async(self, fn, iterable, callback=None):
        self.counter.add(len(iterable))
        return super().starmap_async(self.counter.required(fn), iterable, callback, error_callback=self.error_callback)

    def imap_unordered(self, fn, iterable, chunksize=1):
        self.counter.add(len(iterable))
        return super().imap_unordered(self.counter.required(fn), iterable, chunksize)


    def wait_and_end(self):
        self.counter.wait_for_zero()
        self.close()
        self.join()
