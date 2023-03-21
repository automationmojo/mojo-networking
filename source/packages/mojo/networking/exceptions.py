"""
.. module:: exceptions
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains exceptions that can be raised for exceptional network and protocol
               conditions.

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

from typing import Optional

import os
import requests

class ProtocolError(RuntimeError):
    """
        This error is raised when a communications protocol encounters an error.
    """

class HTTPRequestError(ProtocolError):
    """
        This error is the base error for HTTP requests based errors.
    """
    def __init__(self, message, requrl, status_code, reason, *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.requrl = requrl
        self.status_code = status_code
        self.reason = reason
        return

def raise_for_http_status(context: str, response: requests.Response, details: Optional[dict]=None, allow_redirects: bool=False):
    """
        Raises an :class:`AKitHTTPRequestError` if an HTTP response error occured.
    """

    status_code = response.status_code
    method = response.request.method
    req_url = response.url

    if status_code >= 400 or (not allow_redirects and status_code >= 300):
        err_msg_lines = [
            context
        ]

        reason = response.reason

        # If we have `bytes` then we need to decode it
        if isinstance(reason, bytes):
            try:
                reason = reason.decode('utf-8')
            except UnicodeDecodeError:
                reason = reason.decode('iso-8859-1')

        if status_code < 400:
            # Client Error
            err_msg_lines.append("{} Redirect Error: {} for url: {} method: {}".format(
                status_code, reason, response.url, method))
        elif status_code < 500:
            # Client Error
            err_msg_lines.append("{} Client Error: {} for url: {} method: {}".format(
                status_code, reason, response.url, method))
        elif status_code >= 500 and status_code < 600:
            # Server Error
            err_msg_lines.append("{} Server Error: {} for url: {} method: {}".format(
                status_code, reason, response.url, method))
        else:
            err_msg_lines.append("{} UnExpected Error: {} for url: {} method: {}".format(
                status_code, reason, response.url, method))

        if details is not None:
            for dkey, dval in details.items():
                err_msg_lines.append("    {}: {}".format(dkey, dval))

        errmsg = os.linesep.join(err_msg_lines)
        raise HTTPRequestError(errmsg, req_url, status_code, reason)

    return