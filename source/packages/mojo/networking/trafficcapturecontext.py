"""
.. module:: trafficcapturecontext
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Scope object used for capturing traffic.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []
__version__ = "1.0.0"
__maintainer__ = "Myron Walker"
__email__ = "myron.walker@gmail.com"
__status__ = "Development" # Prototype, Development or Production
__license__ = "MIT"

from typing import Callable, Type

from types import TracebackType

import threading
import weakref

class TrafficCaptureContext:

    def __init__(self, owner: object, identifier: str, fromip: str, destroy_method: Callable):
        self._owner_ref = weakref.ref(owner)
        self._identifier = identifier
        self._fromip = fromip
        self._destroy_method = destroy_method
        self._lock = threading.Lock()
        self._captures = []
        return

    def __enter__(self) -> "TrafficCaptureContext":
        return self
    
    def __exit__(self, ex_type: Type[BaseException], ex_inst: BaseException, ex_tb: TracebackType) -> bool:
        self._destroy_method(self)
        return False

    @property
    def captures(self):
        rtnlist = None

        self._lock.acquire()
        try:
            rtnlist = [c for c in self._captures]
        finally:
            self._lock.release()

        return rtnlist
    
    @property
    def owner(self):
        return self._owner_ref()

    @property
    def fromip(self):
        self._fromip

    @property
    def identifier(self):
        return self._identifier

    def append_capture(self, req_headers: dict, req_body: str):

        self._lock.acquire()
        try:
            self._captures.append((req_headers, req_body))
        finally:
            self._lock.release()

        return