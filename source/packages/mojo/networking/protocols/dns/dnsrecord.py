"""
.. module:: dnsrecord
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains the DnsRecord object which serves as the base object type for other DNS record types.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""


__author__ = "Myron Walker"
__copyright__ = "Copyright 2020, Myron W Walker"
__credits__ = []


from typing import Optional, Union, TYPE_CHECKING

import math
import time

from mojo.networking.protocols.dns.dnsconst import (
    DnsLiftimePercent,
    DnsRecordClass,
    DnsRecordType
)


def current_time_millis() -> float:
    """
        Current system time in milliseconds

        :returns: Time in milliseconds
    """
    now_ms = time.time() * 1000
    return now_ms


if TYPE_CHECKING:
    from mojo.networking.protocols.dns.dnsinboundmessage import DnsInboundMessage
    from mojo.networking.protocols.dns.dnsoutboundmessage import DnsOutboundMessage

class DnsRecord:
    """
        RFC-1035 3.2.1 - A DNS record is a DNS entry that has a Time To Live or TTL attached.

                                         1  1  1  1  1  1
           0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                      NAME                     /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     CLASS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TTL                      |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   RDLENGTH                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        /                     RDATA                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    """
    def __init__(self, name: str, rtype: DnsRecordType, rclass: DnsRecordClass, ttl: Union[float, int]) -> None:
        self._key = name.lower()
        self._name = name
        self._rtype = rtype
        self._rclass = DnsRecordClass(rclass & DnsRecordClass.MASK)
        self._ttl = ttl

        self._unique = (rclass & DnsRecordClass.UNIQUE) != 0
        self._updated = current_time_millis()

        self._when_expires = self._compute_time_marker(DnsLiftimePercent.Expired)
        self._when_refresh = self._compute_time_marker(DnsLiftimePercent.Refresh)
        self._when_stale = self._compute_time_marker(DnsLiftimePercent.Stale)
        return

    @property
    def key(self) -> str:
        return self._key

    @property
    def name(self) -> str:
        return self._name

    @property
    def rclass(self) -> DnsRecordClass:
        return self._rclass

    @property
    def rtype(self) -> DnsRecordType:
        return self._rtype

    @property
    def ttl(self) -> int:
        return self._ttl

    @property
    def unique(self) -> bool:
        return self._unique

    @property
    def updated(self) -> bool:
        return self._updated

    def as_dns_string(self, other: Optional[str] = None) -> str:
        """
            Creates a DNS string representation of the DNS record.
        """
        remaining_ttl = int(self.get_remaining_ttl(current_time_millis()))
        other = "%s/%s,%s" % (self.ttl, remaining_ttl, other)
        
        dnsstr = "%s[%s,%s" % ('record', self._rtype, self._rclass)

        if self._unique:
            dnsstr += "-unique,"
        else:
            dnsstr += ","

        dnsstr += self._name

        if other is not None:
            dnsstr += "]=%s" % other
        else:
            dnsstr += "]"

        return dnsstr

    def get_remaining_ttl(self, now: float) -> int:
        """
            Gets the remaining time to live (TTL) in seconds.
        """
        rval = max(0, math.floor((self._when_expires - now) / 1000))
        return rval

    def is_expired(self, now: Optional[float]) -> bool:
        """
            Returns true if this record is expired.
        """
        if now is None:
            now = time.time()

        bval = self._when_expires <= now
        return bval

    def is_stale(self, now: Optional[float]) -> bool:
        """
            Returns true if this record is stale.
        """
        if now is None:
            now = time.time()

        bval = self._when_stale <= now
        return bval

    def suppressed_by(self, msg: 'DnsInboundMessage') -> bool:
        """
            Returns true if any answer in a message can suffice for the information held in this
            record.
        """
        rtn_val = False
        for record in msg.answers:
            if self.suppressed_by_answer(record):
                rtn_val = True
                break
        return rtn_val

    def suppressed_by_answer(self, other: 'DnsRecord') -> bool:
        """
            Returns true if another record has same name, type and class, and if its TTL is at least
            half of this record's.
        """
        rtnval = self == other and other.ttl > (self.ttl / 2)
        return rtnval

    def update_ttl(self, other: 'DnsRecord') -> None:
        """
            Updates the time to live TTL from the specified record.
        """
        self._updated = other._updated
        self._ttl = other._ttl
        self._when_expires = self._compute_time_marker(DnsLiftimePercent.Expired)
        self._when_refresh = self._compute_time_marker(DnsLiftimePercent.Refresh)
        self._when_stale = self._compute_time_marker(DnsLiftimePercent.Stale)
        return

    def write(self, out: 'DnsOutboundMessage') -> None:
        """
            Abstract method
        """
        errmsg = "The 'DnsRecord.write' method must be implemented in derived classes."
        raise NotImplementedError(errmsg)

    def _compute_time_marker(self, percent: int) -> int:
        marker = math.floor(self._updated + (percent * self._ttl * 10))
        return marker

    def __eq__(self, other: 'DnsRecord') -> bool:
        """
            Equality test on name, record type, and record class
        """
        iseq = False
        if isinstance(other, type(self)):
            if self._rtype == other._rtype and self._rclass and other._rclass:
                iseq = self._name == other._name
        return iseq

    def __ne__(self, other: 'DnsRecord') -> bool:
        """
            Non-equality test
        """
        isne = not self.__eq__(other)
        return isne

    def __str__(self) -> str:
        """
            String representation
        """
        dnsstr = self.as_dns_string()
        return dnsstr
