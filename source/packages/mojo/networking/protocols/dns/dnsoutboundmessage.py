"""
.. module:: dnsoutgoing
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains the DnsOutgoing object which is used to write out DNS records of different types into
               a DNS packet.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2020, Myron W Walker"
__credits__ = []


from typing import Any, Dict, List, Optional, Tuple, Union

import logging
import struct

from enum import IntEnum

from mojo.networking.protocols.dns.dnsconst import DnsRecordClass, DnsRecordType, DNS_PACKET_HEADER_SIZE, MAX_MSG_ABSOLUTE, MAX_MSG_TYPICAL
from mojo.networking.protocols.dns.dnsflags import DnsFlags

from mojo.networking.protocols.dns.exceptions import DnsNamePartTooLongError
from mojo.networking.protocols.dns.dnsquestion import DnsQuestion
from mojo.networking.protocols.dns.dnsrecord import DnsRecord
from mojo.networking.protocols.dns.dnspointer import DnsPointer

logger = logging.getLogger()

struct_int_to_byte = struct.Struct(">B")

class DnsPacketBuilderState(IntEnum):
    Initial = 0
    Finished = 1


class DnsOutboundMessage:
    """
        The :class:`DnsOutboundMessage` object is used to format outgoing DNS packets into octet streams.
    """

    def __init__(self, flags: DnsFlags, id: int=0, multicast: bool = True, use_compression: Optional[bool] = None) -> None:
        """
        """
        self._finished = False
        self._id = id
        self._multicast = multicast
        
        if use_compression is not None:
            self._use_compression = use_compression
        elif self._multicast is True:
            self._use_compression = True # Always use compression with multicast DNS
        else:
            self._use_compression = False

        self._flags = flags

        # Stream state and data fields
        self._state = DnsPacketBuilderState.Initial
        self._packets_data: List[bytes] = [] 

        # these 3 are per-packet fields -- see also reset_for_next_packet()
        self._compression_names: Dict[str, int] = {}
        self._data: List[bytes] = []
        self._packet_offset = DNS_PACKET_HEADER_SIZE

        # Message Data
        self._questions: List[DnsQuestion] = []
        self._answers: List[Tuple[DnsRecord, float]] = [] 
        self._authorities: List[DnsPointer] = [] 
        self._additionals: List[DnsRecord] = []
        
        return

    @property
    def additionals(self) -> List[DnsRecord]:
        return self._additionals

    @property
    def answers(self) -> List[Tuple[DnsRecord, float]]:
        return self._answers

    @property
    def authorities(self) -> List[DnsPointer] :
        return self._authorities

    @property
    def data(self) -> List[bytes]:
        return self._data

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def flags(self) -> DnsFlags:
        return self._flags

    @property
    def id(self) -> int:
        return self._id

    @property
    def multicast(self) -> bool:
        return self._multicast

    @property
    def packets_data(self) -> List[bytes]:
        return self._packets_data

    @property
    def questions(self) -> List[DnsQuestion]:
        return self._questions

    @property
    def size(self) -> int:
        return self._packet_offset

    @property
    def state(self) -> DnsPacketBuilderState:
        return self._state

    @staticmethod
    def is_type_unique(rtype: int) -> bool:
        rtnval = rtype == DnsRecordType.TXT or rtype == DnsRecordType.SRV or rtype == DnsRecordType.A or rtype == DnsRecordType.AAAA
        return rtnval

    def add_question(self, record: DnsQuestion) -> None:
        """
            Adds a question
        """
        self._questions.append(record)
        return

    def add_answer(self, record: 'DnsRecord') -> None:
        """
            Adds an answer
        """
        self.add_answer_at_time(record, 0)
        return

    def add_additional_answer(self, record: 'DnsRecord') -> None:
        """
        Adds an additional answer

        From: RFC 6763, DNS-Based Service Discovery, February 2013

        12.  DNS Additional Record Generation

           DNS has an efficiency feature whereby a DNS server may place
           additional records in the additional section of the DNS message.
           These additional records are records that the client did not
           explicitly request, but the server has reasonable grounds to expect
           that the client might request them shortly, so including them can
           save the client from having to issue additional queries.

           This section recommends which additional records SHOULD be generated
           to improve network efficiency, for both Unicast and Multicast DNS-SD
           responses.

        12.1.  PTR Records

           When including a DNS-SD Service Instance Enumeration or Selective
           Instance Enumeration (subtype) PTR record in a response packet, the
           server/responder SHOULD include the following additional records:

           o  The SRV record(s) named in the PTR rdata.
           o  The TXT record(s) named in the PTR rdata.
           o  All address records (type "A" and "AAAA") named in the SRV rdata.

        12.2.  SRV Records

           When including an SRV record in a response packet, the
           server/responder SHOULD include the following additional records:

           o  All address records (type "A" and "AAAA") named in the SRV rdata.

        """
        self._additionals.append(record)
        return

    def add_answer_at_time(self, record: Optional['DnsRecord'], now: Union[float, int]) -> None:
        """
            Adds an answer if it does not expire by a certain time
        """
        if record is not None:
            if now == 0 or not record.is_expired(now):
                self._answers.append((record, now))
        return

    def add_authorative_answer(self, record: DnsPointer) -> None:
        """
            Adds an authoritative answer
        """
        self._authorities.append(record)
        return

    def packets(self) -> List[bytes]:
        """
            Returns a list of bytestrings containing the packets' bytes

            No further parts should be added to the packet once this is done.  The packets are each restricted to
            MAX_MSG_TYPICAL or less in length, except for the case of a single answer which will be written out to
            a single oversized packet no more than MAX_MSG_ABSOLUTE in length (and hence will be subject to IP
            fragmentation potentially).
        """

        if self._state == DnsPacketBuilderState.Finished:
            return self._packets_data

        questions_offset = 0
        answer_offset = 0
        authority_offset = 0
        additional_offset = 0

        # we have to at least write out the question
        first_iteration = True

        while (
            questions_offset < len(self._questions)
            or answer_offset < len(self._answers)
            or authority_offset < len(self._authorities)
            or additional_offset < len(self._additionals)
        ):
            
            logger.debug("offsets = %d, %d, %d", answer_offset, authority_offset, additional_offset)
            logger.debug("lengths = %d, %d, %d", len(self._answers), len(self._authorities), len(self._additionals))

            additionals_written = 0
            authorities_written = 0
            answers_written = 0
            questions_written = 0

            # Write out all the questions, we expect questions to be kept to a minimum for each outbound DnsMessage
            for question in self._questions:
                self._write_question(question)
                questions_written += 1

            allow_long = True  # at most one answer must be allowed even if it creates a long DNS packet
            for answer, time_ in self._answers[answer_offset:]:
                if self._write_record(answer, time_, allow_long):
                    answers_written += 1
                allow_long = False

            for authority in self._authorities[authority_offset:]:
                if self._write_record(authority, 0):
                    authorities_written += 1

            for additional in self._additionals[additional_offset:]:
                if self._write_record(additional, 0):
                    additionals_written += 1

            # Insert the Flags and Header at the beginning of the packet stream
            self._insert_short(0, additionals_written)
            self._insert_short(0, authorities_written)
            self._insert_short(0, answers_written)
            self._insert_short(0, questions_written)

            flags_int = self._flags.flags()
            self._insert_short(0, flags_int)

            if self._multicast:
                self._insert_short(0, 0)
            else:
                self._insert_short(0, self._id)

            # Roll up all the buffers into a bytestream and add it to our packets_data
            self._packets_data.append(b''.join(self._data))
            self._reset_for_next_packet()

            questions_offset += questions_written
            answer_offset += answers_written
            authority_offset += authorities_written
            additional_offset += additionals_written

            logger.debug("now offsets = %d, %d, %d", answer_offset, authority_offset, additional_offset)
            if (answers_written + authorities_written + additionals_written) == 0 and (
                len(self._answers) + len(self._authorities) + len(self._additionals)
            ) > 0:
                logger.warning("packets() made no progress adding records; returning")
                break

        self._state = DnsPacketBuilderState.Finished

        return self._packets_data

    def _insert_short(self, index: int, value: int) -> None:
        """
            Inserts an unsigned short in a certain position in the packet
        """
        self._data.insert(index, struct.pack(b'!H', value))
        self._packet_offset += 2
        return

    def _pack(self, format_: Union[bytes, str], value: Any) -> None:
        self._data.append(struct.pack(format_, value))
        self._packet_offset += struct.calcsize(format_)
        return

    def _reset_for_next_packet(self) -> None:
        self._compression_names = {}
        self._data = []
        self._packet_offset = 12 # Initialize to 12 to account for the packet header size

    def _write_bytes(self, buffer: bytes) -> None:
        """
            Writes a string to the packet
        """
        assert isinstance(buffer, bytes)
        self._data.append(buffer)
        self._packet_offset += len(buffer)
        return

    def _write_compressed_name(self, name: str, parts: List[str]) -> None:

        if name not in self._compression_names:
            self._compression_names[name] = self._packet_offset

            # Top level names are just written out.        
            if len(parts) == 1:    
                self._write_utf(name)
                self._write_single_byte(0) # Terminate the name with a '0' octect
            
            # If we are not a top level name, write out our parent first, then write ourselves and
            # terminate with a parent pointer
            elif len(parts) > 1:
                toplabel = parts[0]
                self._write_utf(toplabel)

                pparts = parts[1:]
                pname = '.'.join(pparts)
                
                if pname in self._compression_names:
                    pindex = self._compression_names[pname]
                    self._write_compressed_name_index(pindex)  # Terminate the name with a compressed name pointer
                else:
                    self._write_compressed_name(pname, pparts)

            else:
                raise RuntimeError("We should never get called with a parts length of '0'")
        
       
        return

    def _write_compressed_name_index(self, name_index: int) -> None:
        self._write_single_byte((name_index >> 8) | 0xC0)
        self._write_single_byte(name_index & 0xFF)
        return

    def _write_int(self, value: Union[float, int]) -> None:
        """
            Writes an unsigned integer to the packet
        """
        self._pack(b'!I', int(value))
        return

    def _write_name(self, name: str) -> None:
        """
            Write names to packet

            18.14. Name Compression

            When generating Multicast DNS messages, implementations SHOULD use name compression wherever possible to
            compress the names of resource records, by replacing some or all of the resource record name with a
            compact two-byte reference to an appearance of that data somewhere earlier in the message [RFC1035].
        """

        if self._use_compression:
            name = name.rstrip(".")

            # If the full name if found in the compression names, then we have already
            # written out the name and all its parts.
            name_index: Union[int, None] = self._compression_names.get(name, None)
            if name_index is not None:
                self._write_compressed_name_index(name_index)

            else:
                parts = name.split('.')
                self._write_compressed_name(name, parts)

        else:
            self._write_utf(name)
            self._write_single_byte(0)

        return

    def _write_question(self, question: DnsQuestion) -> None:
        """
            Writes a question to the packet
        """
        self._write_name(question.name)
        self._write_short(question.rtype)
        self._write_short(question.rclass)
        return

    def _write_record(self, record: 'DnsRecord', now: float, allow_long: bool = False) -> bool:
        """
            Writes a record (answer, authoritative answer, additional) to the packet.  Returns True on success, or False if
            we did not (either because the packet was already finished or because the record does not fit.)
        """
        if self._state == self._state.finished:
            return False

        start_data_length, start_size = len(self._data), self._packet_offset
        self._write_name(record.name)
        self._write_short(record.rtype)

        if record.unique and self._multicast:
            self._write_short(record.rclass | DnsRecordClass.UNIQUE)
        else:
            self._write_short(record.rclass)

        if now == 0:
            self._write_int(record.ttl)
        else:
            self._write_int(record.get_remaining_ttl(now))

        index = len(self._data)

        # Adjust size for the short we will write before this record
        self._packet_offset += 2
        record.write(self)
        self._packet_offset -= 2

        length = sum((len(d) for d in self._data[index:]))
        # Here is the short we adjusted for
        self._insert_short(index, length)

        len_limit = MAX_MSG_ABSOLUTE if allow_long else MAX_MSG_TYPICAL

        # if we go over, then rollback and quit
        if self._packet_offset > len_limit:
            while len(self._data) > start_data_length:
                self._data.pop()
            self._packet_offset = start_size
            return False

        return True

    def _write_short(self, value: int) -> None:
        """
            Writes an unsigned short to the packet
        """
        self._pack(b'!H', value)
        return

    def _write_single_byte(self, value: int) -> None:
        """
            Writes a single byte to the packet
        """
        # TODO: Optimize this
        self._pack(b'!c', struct_int_to_byte.pack(value))
        return

    def _write_utf(self, s: str) -> None:
        """
            Writes a UTF-8 string of a given length to the packet
        """
        bytes = s.encode('utf-8')
        length = len(bytes)
        if length > 64:
            raise DnsNamePartTooLongError
        self._write_single_byte(length)
        self._write_bytes(bytes)
        return
    
    def __str__(self) -> str:
        strval = '<DnsOutboundMessage:{%s}>' % ', '.join(
            [
                'multicast=%s' % self._multicast,
                'flags=%s' % self._flags,
                'questions=%s' % self._questions,
                'answers=%s' % self._answers,
                'authorities=%s' % self._authorities,
                'additionals=%s' % self._additionals,
            ]
        )
        return strval