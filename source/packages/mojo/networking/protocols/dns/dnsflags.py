
from typing import Optional


from mojo.networking.protocols.dns.dnsconst import DnsQr, DnsOpCode, DnsRespCode


class DnsFlags:
    """
        Note: The bits are in order specified below

           1  1  1  1  1  1
           5  4  3  2  1  0  9  8  7  6  5  4  3  2  1  0
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
          |   RCODE   |   Z    |RA|RD|TC|AA|   Opcode  |QR|
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 
    """

    def __init__(self, *, qr: DnsQr, opcode: DnsOpCode, aa: bool, tc: bool, rd: bool, ra: bool, rcode: DnsRespCode, z: int=0, flags: Optional[int]=None):
        """
            Sets the flags for the DNS header.

            :param qr: Indicates if the message is a query or a response
            :param opcode: Specifies the opcode for the message
            :param aa: Specifies that the message is an authoritative answer
            :param tc: Specifies that the message is truncated
            :param rd: Specifies that recursion is desired (set in queries only)
            :param ra: Specifies that recursion is available (set in responses only)
            :param rcode: The response code associated with the message
            :param z: Not used, should be zero
            :param flags: Only used by DnsFlags.parse to bypass duplicate work of rebuilding a flags int.

        """
        self._qr = qr
        self._opcode = opcode
        self._aa = aa
        self._tc = tc
        self._rd = rd
        self._ra = ra
        self._rcode = rcode
        self._z = z
       
        if flags is not None:
            self._flags = self._compile_flags(flags)

        return

    @property
    def aa(self) -> bool:
        """
            Indicates that the messgae is an authoritative answer.
        """
        return self._aa

    @property
    def opcode(self) -> DnsOpCode:
        """
            The opcode for the message.
        """
        return self._opcode
    
    @property
    def qr(self) -> DnsQr:
        """
            Indicates if the message is a query or response.
        """
        return self._qr
    
    @property
    def ra(self) -> bool:
        """
            Specifies that recursion is available (set in responses only).
        """
        return self._ra
    
    @property
    def rcode(self) -> DnsRespCode:
        """
            The response code associated with the message
        """
        return self._rcode

    @property
    def rd(self) -> bool:
        """
            Specifies that recursion is desired (set in queries only).
        """
        return self._rd


    @property
    def tc(self) -> bool:
        """
            Specifies that the message is truncated.
        """
        return self._tc
    
    @property
    def z(self) -> int:
        """
            Not used, should be zero.
        """
        return self._z

    def flags(self) -> int:
        """
            Converts a :class:`DnsFlags` object to a flags integer.
        """
        
        flags: int = (self._rcode << 12) & 0xF000
        flags |= (self._z << 9) & 0x0E00
        flags |= (int(self._ra) << 8) & 0x0100
        flags |= (int(self._rd) << 7) & 0x0080
        flags |= (int(self._tc) << 6) & 0x0040
        flags |= (int(self._aa) << 5) & 0x0020
        flags |= (self._opcode << 1) & 0x001E
        flags |= self._qr & 0x0001

        return flags

    def _compile_flags(self, flags: int):

        self._rcode = DnsRespCode((flags & 0xF000) >> 12)
        z = int((flags & 0x0E00) >> 9)
        ra = True if (flags & 0x0100) >> 8 else False
        rd = True if (flags & 0x0080) >> 7 else False 
        tc = True if (flags & 0x0040) >> 6 else False 
        aa = True if (flags & 0x0020) >> 5 else False 
        opcode = DnsOpCode((flags & 0x001E) >> 1)  
        qr = DnsQr(flags & 0x0001)

        return flags

    @classmethod
    def parse(cls, flags: int) -> "DnsFlags":
        """
            Parses a flags integer and converts it to a :class:`DnsFlags` object.
        """
        rcode = DnsRespCode((flags & 0xF000) >> 12)
        z = int((flags & 0x0E00) >> 9)
        ra = True if (flags & 0x0100) >> 8 else False
        rd = True if (flags & 0x0080) >> 7 else False 
        tc = True if (flags & 0x0040) >> 6 else False 
        aa = True if (flags & 0x0020) >> 5 else False 
        opcode = DnsOpCode((flags & 0x001E) >> 1)  
        qr = DnsQr(flags & 0x0001)

        fobj = DnsFlags(qr=qr, opcode=opcode, aa=aa, tc=tc, rd=rd, ra=ra, rcode=rcode, z=z, flags=flags)

        return fobj
    
    def __repr__(self):
        
        repval = f"DnsFlags(qr={self._qr}, opcode={self._opcode}, aa={self._aa}, tc={self._tc}," \
            f" rd={self._rd}, ra={self._ra}, rcode={self._rcode}, z={self._z})"

        return repval

    def __str__(self) -> str:
        return repr(self)


DEFAULT_DNS_FLAGS_QUERY = DnsFlags(qr=DnsQr.Query, opcode=DnsOpCode.IQuery, aa=False, tc=False, rd=False, ra=False, rcode=DnsRespCode.NoError)
