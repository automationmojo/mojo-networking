"""
.. module:: dnstext
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains the DnsText objec which reprsents a DNS text record type.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2020, Myron W Walker"
__credits__ = []


from typing import TYPE_CHECKING

from mojo.networking.protocols.dns.dnsrecord import DnsRecord

if TYPE_CHECKING:
    from mojo.networking.protocols.dns.dnsoutboundmessage import DnsOutboundMessage

class DnsText(DnsRecord):
    """
        A DNS text record
    """

    def __init__(self, name: str, rtype: int, rclass: int, ttl: int, text: bytes) -> None:
        assert isinstance(text, (bytes, type(None)))
        DnsRecord.__init__(self, name, rtype, rclass, ttl)
        self._text = text

    @property
    def text(self) -> str:
        return self._text

    def write(self, out: 'DnsOutboundMessage') -> None:
        """
            Used in constructing an outgoing packet
        """
        out.write_string(self._text)

    def __eq__(self, other: DnsRecord) -> bool:
        """
            Tests equality on text
        """
        # Call DnsRecord equality operator first because it can eliminate alot of equality checks early
        iseq = False
        if DnsRecord.__eq__(self, other):
            iseq = self._text == other._text
        return iseq

    def __ne__(self, other: DnsRecord) -> bool:
        """
            Non-equality test
        """
        isne = not self.__eq__(other)
        return isne

    def __str__(self) -> str:
        """
            String representation
        """
        strval = None
        if len(self._text) > 10:
            strval = self.as_dns_string(self._text[:7] + "...")
        else:
            strval = self.as_dns_string(self._text)
        return strval
