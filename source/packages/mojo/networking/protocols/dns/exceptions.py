"""
.. module:: exceptions
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains the error types utilized by the multicast DNS code.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2020, Myron W Walker"
__credits__ = []



from mojo.networking.exceptions import ProtocolError

class DnsProtocolError(ProtocolError):
    """
        Base error for all DNS protocol errors.
    """

class DnsDecodeError(DnsProtocolError):
    """
        Error raised when the decoding of a DNS response fails.
    """
class DnsNonUniqueNameError(DnsProtocolError):
    """
        A non-unique name was encountered.
    """

class DnsNamePartTooLongError(DnsProtocolError):
    """
        The name part was too long
    """

class DnsBadTypeInNameError(DnsProtocolError):
    """
        Bad type in name
    """
