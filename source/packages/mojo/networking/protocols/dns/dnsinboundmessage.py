"""
.. module:: dnsincoming
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains the DnsIncoming object which is used to represent an incoming DNS packet and to provide
               methods for processing the packet.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2020, Myron W Walker"
__credits__ = []



from typing import List, Optional, Tuple, Union

import logging
import os
import struct

from mojo.networking.protocols.dns.dnsconst import (
    DnsQr,
    DnsRecordType,
    DnsRecordClass,
    DNS_PACKET_HEADER_SIZE,
    DNS_COMP_MASK,
    DNS_OFFSET_MASK
)

from mojo.networking.protocols.dns.dnsflags import DnsFlags
from mojo.networking.protocols.dns.exceptions import DnsDecodeError

from mojo.networking.protocols.dns.dnsaddress import DnsAddress
from mojo.networking.protocols.dns.dnshostinfo import DnsHostInfo
from mojo.networking.protocols.dns.dnspointer import DnsPointer
from mojo.networking.protocols.dns.dnsquestion import DnsQuestion
from mojo.networking.protocols.dns.dnsrecord import DnsRecord
from mojo.networking.protocols.dns.dnsservice import DnsService
from mojo.networking.protocols.dns.dnstext import DnsText

logger = logging.getLogger()

class DnsInboundMessage:
    """
        The :class:`DnsInboundMessage` object is used to read incoming DNS packets.
    """

    def __init__(self, data: bytes, source_endpoint: Union[str, bytes, Tuple[str, int], None] = None) -> None:
        """
            Constructor from string holding bytes of packet
        """
        self._offset: int = 0

        self._data: bytes = data
        self._questions: List[DnsQuestion] = []
        self._answers: List[DnsRecord] = []
        self._id: int = 0
        self._flags: DnsFlags = None  # type: int
        self._num_questions: int = 0
        self._num_answers: int = 0
        self._num_authorities: int = 0
        self._num_additionals: int = 0
        self._valid: bool = False
        self._source = "unknown"

        if source_endpoint is not None:
            if isinstance(source_endpoint, str):
                self._source = source_endpoint
            elif isinstance(source_endpoint, bytes):
                self._source = source_endpoint.decode('utf-8')
            else:
                self._source = f"{source_endpoint[0], source_endpoint[1]}"

        try:
            self._ingest_header()
            self._ingest_questions()
            self._ingest_others()

            self._valid = True

        except (IndexError, struct.error, DnsDecodeError):
            logger.exception('Choked at offset %d while unpacking %r', self._offset, data)
            pass

        return

    @property
    def answers(self) -> List[DnsRecord]:
        return self._answers

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def flags(self) -> DnsFlags:
        return self._flags

    @property
    def id(self) -> int:
        return self._id

    @property
    def questions(self) -> List[DnsQuestion]:
        return self._questions

    def is_query(self) -> bool:
        """
            Returns true if this is a query
        """
        result = self.flags._qr == DnsQr.Query
        return result

    def is_response(self) -> bool:
        """
            Returns true if this is a response
        """
        result = self.flags._qr == DnsQr.Response
        return result

    def _ingest_header(self) -> None:
        """
            Processes the header portion of the message
        """

        self._id = struct.unpack_from(b'!H', self._data, self._offset)[0]
        self._offset += 2

        flags_int = struct.unpack_from(b'!H', self._data, self._offset)[0]
        self._offset += 2
        self._flags = DnsFlags.parse(flags_int)
        
        self._num_questions = struct.unpack_from(b'!H', self._data, self._offset)[0]
        self._offset += 2

        self._num_answers = struct.unpack_from(b'!H', self._data, self._offset)[0]
        self._offset += 2

        self._num_authorities = struct.unpack_from(b'!H', self._data, self._offset)[0]
        self._offset += 2 

        self._num_additionals = struct.unpack_from(b'!H', self._data, self._offset)[0]
        self._offset += 2

        return

    def _ingest_questions(self) -> None:
        """
            Processes the questions section of the message
        """

        for i in range(self._num_questions):
            name = self._read_name()
            rtype, rclass = self._read_type_and_class()

            question = DnsQuestion(name, rtype, rclass)
            self._questions.append(question)
        
        return
    
    def _ingest_others(self) -> None:
        """
            Processes the answers, authorities and additionals section of the message
        """
        n = self._num_answers + self._num_authorities + self._num_additionals
        for i in range(n):
            record_offset = self._offset

            domain = self._read_name()

            rtype, rclass = self._read_type_and_class()
            ttl = self._read_ttl()
            length = self._read_unsigned_short()

            if rtype == DnsRecordType.SRV:
                priority = self._read_unsigned_short()
                weight = self._read_unsigned_short()
                port = self._read_unsigned_short()
                server = self._read_name()

                rec = DnsService(
                    domain,
                    rtype,
                    rclass,
                    ttl,
                    priority,
                    weight,
                    port,
                    server,
                )
            else:

                rec = None  # type: Optional[DnsRecord]
                if rtype == DnsRecordType.A:
                    address = self._read_string_characters(4)
                    rec = DnsAddress(domain, rtype, rclass, ttl, address)

                elif rtype == DnsRecordType.AAAA:
                    address = self._read_string_characters(16)
                    rec = DnsAddress(domain, rtype, rclass, ttl, address)

                elif rtype == DnsRecordType.CNAME or rtype == DnsRecordType.PTR:
                    alias = self._read_name()
                    rec = DnsPointer(domain, rtype, rclass, ttl, alias)

                elif rtype == DnsRecordType.TXT:
                    text = self._read_string_characters(length)

                    rec = DnsText(domain, rtype, rclass, ttl, text)

                elif rtype == DnsRecordType.HINFO:
                    host_cpu = self._read_string().decode('utf-8')
                    host_os = self._read_string().decode('utf-8')

                    rec = DnsHostInfo(
                        domain,
                        rtype,
                        rclass,
                        ttl,
                        host_cpu,
                        host_os,
                    )

                else:
                    # Try to ignore types we don't know about
                    # Skip the payload for the resource record so the next
                    # records can be parsed correctly
                    self._offset += length

            if rec is not None:
                self.answers.append(rec)

        return
    

    def _read_name(self) -> str:
        """
            Reads a domain name from the packet
        """
        result = ''
        start = self._offset
        cursor = start

        result, consumed = self._read_name_at_offset(start, cursor, [])

        if consumed == 0:
            raise DnsDecodeError(f"DnsInboundMessage[{self._source}] Empty name. start={start} consumed={consumed}")

        self._offset += consumed

        return result


    def _read_name_at_offset(self, start: int, cursor: int, followed: List[int]) -> str:

        result = ''
        consumed = 0

        while True:

            first_octet = self._data[cursor]
            if len(followed) == 0:
                consumed += 1

            if first_octet == 0x00:
                break

            comp_flags = (first_octet & DNS_COMP_MASK)

            if comp_flags == 0x00:
                comp_start = cursor + 1
                comp_length = first_octet & DNS_OFFSET_MASK
                comp_val = self._read_utf(comp_start, comp_length)
                result = f"{result}{comp_val}."

                cursor = comp_start + comp_length

                # We only consume bytes of the packet if we have not yet followed a pointer.
                if len(followed) == 0:
                    consumed += comp_length
            
            elif comp_flags == DNS_COMP_MASK:
                second_octet = self._data[cursor + 1]
                if len(followed) == 0:
                    consumed += 1

                offset_ptr = ((first_octet & DNS_OFFSET_MASK) << 8) + second_octet
                if offset_ptr >= start:
                    err_msg_lines = [
                        f"DnsInboundMessage[{self._source}] Invalid name compression offset pointer.",
                        f"    NAME START: {start}",
                        f"    OFFSET POINTER: {offset_ptr}",
                        f"    FOLLOWED: {followed}"
                    ]
                    err_msg = os.linesep.join(err_msg_lines)
                    raise DnsDecodeError(err_msg)
                followed.append(offset_ptr)
                comp_val, _ = self._read_name_at_offset(start, offset_ptr, followed)
                result = result = f"{result}{comp_val}"

                break  # Once we hit a pointer, then that is the end of the name

            else:
                err_msg_lines = [
                        f"DnsInboundMessage[{self._source}] Invalid name compression flags.",
                        f"    NAME START: {start}",
                        f"    FLAGS: {comp_flags}",
                        f"    FOLLOWED: {followed}"
                    ]
                err_msg = os.linesep.join(err_msg_lines)
                raise DnsDecodeError(err_msg)

        return result, consumed


    def _read_string(self) -> bytes:
        """
            Reads a character string from the packet
        """
        length = int(self._data[self._offset])
        self._offset += 1

        strval = self._read_string_characters(length)

        return strval

    def _read_string_characters(self, length: int) -> bytes:
        """
            Reads a string of a given length from the packet
        """
        strval = self._data[self._offset : self._offset + length]
        self._offset += length
        return strval

    def _read_ttl(self) -> int:
        """
            Reads an integer ttl from the packet
        """
        # Unpack 4 bytes as unsigned int using network byte order !I
        val = int(self._unpack(b'!i')[0])

        return val

    def _read_type_and_class(self) -> Tuple[DnsRecordType, DnsRecordClass]:
        """
            Reads an integer ttl from the packet
        """

        rtype, rclass = self._unpack(b'!HH')

        try:
            rtype = DnsRecordType(rtype)
            rclass = DnsRecordClass(rclass)
        except ValueError:
            pass # Unable to convert record and class

        return rtype, rclass

    def _read_unsigned_int(self) -> int:
        """
            Reads an integer from the packet
        """
        # Unpack 4 bytes as unsigned int using network byte order !I
        val = int(self._unpack(b'!I')[0])
        return val

    def _read_unsigned_short(self) -> int:
        """
            Reads an unsigned short from the packet
        """
        # Unpack 2 bytes as unsigned short using network byte order !H
        val = int(self._unpack(b'!H')[0])
        return val

    def _read_utf(self, offset: int, length: int) -> str:
        """
            Reads a UTF-8 string of a given length from the packet
        """
        utfval = str(self._data[offset : offset + length], 'utf-8', 'replace')
        return utfval

    def _unpack(self, format_: bytes) -> tuple:
        length = struct.calcsize(format_)
        info = struct.unpack(format_, self._data[self._offset : self._offset + length])
        self._offset += length
        return info

    def __str__(self) -> str:
        strval = '<DnsInboundMessage:{%s}>' % ', '.join(
            [
                'id=%s' % self._id,
                'flags=%s' % self._flags,
                'n_q=%s' % self._num_questions,
                'n_ans=%s' % self._num_answers,
                'n_auth=%s' % self._num_authorities,
                'n_add=%s' % self._num_additionals,
                'questions=%s' % self._questions,
                'answers=%s' % self._answers,
            ]
        )
        return strval



if __name__ == "__main__":

    packet = b"\x00\x00\x84\x00\x00\x00\x00\x02\x00\x00\x00\x04'HP Color LaserJet Pro M478f-9f [834BAB]\x04_ipp\x04_tcp\x05local\x00\x00\x10\x80\x01\x00\x00\x11\x94\x02\xda\ttxtvers=15adminurl=http://HP0068EB834BAB.local./#hId-pgAirPrint\x05note=\x0bpriority=20\x08qtotal=1\x07TLS=1.2\x0crp=ipp/print)UUID=5f1123e1-7b3c-5b59-698a-e4916b1b0e1a(product=(HP Color LaserJet Pro M478f-9f)!ty=HP Color LaserJet Pro M478f-9f\nusb_MFG=HP#usb_MDL=Color LaserJet Pro M478f-9f\x07Color=T\x08Duplex=T\xfepdl=application/vnd.hp-PCL,application/vnd.hp-PCLXL,application/postscript,application/msword,application/pdf,image/jpeg,image/urf,image/pwg-raster,application/PCLm,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.m\x11PaperMax=legal-A4dURF=CP1,MT1-2-8-9-10-11,PQ3-4-5,RS600,SRGB24,OB10,W8,DEVW8,DEVRGB24,ADOBERGB24,DM3,IS19-1-2,V1.4,FN3\rkind=document\x06Scan=T\x14mopria-certified=2.0\x0erfo=ipp/faxout\x05Fax=T\xc0\x0c\x00!\x80\x01\x00\x00\x00x\x00\x17\x00\x00\x00\x00\x02w\x0eHP0068EB834BAB\xc0>\xc3;\x00\x01\x80\x01\x00\x00\x00x\x00\x04\xac\x10\x01\x03\xc3;\x00\x1c\x80\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x02h\xeb\xff\xfe\x83K\xac\xc0\x0c\x00/\x80\x01\x00\x00\x11\x94\x00\t\xc0\x0c\x00\x05\x00\x00\x80\x00@\xc3;\x00/\x80\x01\x00\x00\x00x\x00\x08\xc3;\x00\x04@\x00\x00\x08"

    msg = DnsInboundMessage(packet)
