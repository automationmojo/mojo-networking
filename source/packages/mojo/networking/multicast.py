"""
.. module:: multicast
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains helper functions for working with multicast sockets

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

import errno
import socket
import struct

from mojo.networking.constants import IPPROTO_IPV6, SO_RECV_ANYIF
from mojo.networking.interfaces import get_ipv4_address
from mojo.networking.interfaces import get_ipv6_address


def create_multicast_socket(multicast_addr: str, port: int, bind_addr: str='', family: socket.AddressFamily = socket.AF_INET,
    ttl: Optional[int] = None, loop: Optional[int] = None, timeout: Optional[float] = None, apple_p2p: bool = False) -> socket.socket:
    """
        Create a socket for listening for multi-cast packets sent to the specified group on the specified interface
        and with the specified settings.

        :param multicast_addr: The multicast group address the socket will be used to communicate with.
        :param ifname: The name if the interface to create the socket for.
        :param port: The port to bind the socket with.
        :param bind_addr: The address to bind the multicast socket too. The default is all addresses.
        :param family: The internet address family for the socket, either (socket.AF_INET or socket.AF_INET6)
        :param ttl: The time to live that will be attached to the packets sent by this socket.
                    0 = same host
                    1 = same subnet
                    32 = same site
                    64 = same region
                    128 = same continent
                    255 = unrestricted scope
        :param loop: Boolean value indicating if the loopback address should be included for traffic.
        :param timeout: The socket timeout to assign to the socket
        :param apple_p2p: A boolean value indicating if the socket option for Apple Peer-2-Peer should be set.

    """

    bind_addr = '0.0.0.0'
    sock = None

    if family == socket.AF_INET:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    elif family == socket.AF_INET6:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        raise RuntimeError("Socket family not supported. family=%r" % family) from None

    # We need to set SO_REUSEADDR to allow the re-use of addresses by multiple processes.  This allows
    # more than one application to listen on multi-cast port addresses that are designated for specific
    # protocols.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # SO_REUSEADDR should be equivalent to SO_REUSEPORT for multicast UDP sockets
    # (p 731, "TCP/IP Illustrated, Volume 2").  Some BSD-derived systems require
    # SO_REUSEPORT to be specified explicitly.  Also, not all versions of Python
    # have SO_REUSEPORT available.
    # Catch OSError for when an OS is encountered that does not support SO_REUSEPORT support.
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError as os_err:
            if not os_err.errno == errno.ENOPROTOOPT:
                err_msg = "Error attempting to set socket option 'SO_REUSEPORT'. errno=%d" % os_err.errno
                raise RuntimeError(err_msg) from os_err

    if ttl is not None:
        if family == socket.AF_INET:
            ttl = struct.pack(b'b', ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        else:
            sock.setsockopt(IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)

    if loop is not None:
        if family == socket.AF_INET:
            loop = struct.pack(b'b', loop)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
        else:
            sock.setsockopt(IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, loop)

    if apple_p2p:
        sock.setsockopt(socket.SOL_SOCKET, SO_RECV_ANYIF, 1)

    if timeout is not None:
        sock.settimeout(timeout)

    sock.bind((bind_addr, port))

    # We also need to tell the Kernel to bind the INBOUND traffic destined for the multi-cast
    # group to the address for this interface, so we receive responses
    member_in = socket.inet_aton(multicast_addr) + socket.inet_aton(bind_addr)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, member_in)

    return sock

def create_multicast_socket_for_iface(multicast_addr: str, ifname: str, port: int, family: socket.AddressFamily = socket.AF_INET,
    ttl: Optional[int] = None, loop: Optional[int] = None, timeout: Optional[float] = None, apple_p2p: bool = False) -> socket.socket:
    """
        Create a socket for listening for multi-cast packets sent to the specified group on the specified interface
        and with the specified settings.

        :param multicast_addr: The multicast group address the socket will be used to communicate with.
        :param ifname: The name if the interface to create the socket for.
        :param port: The port to bind the socket with.
        :param family: The internet address family for the socket, either (socket.AF_INET or socket.AF_INET6)
        :param ttl: The time to live that will be attached to the packets sent by this socket.
                    0 = same host
                    1 = same subnet
                    32 = same site
                    64 = same region
                    128 = same continent
                    255 = unrestricted scope
        :param loop: Boolean value indicating if the loopback address should be included for traffic.
        :param timeout: The socket timeout to assign to the socket
        :param apple_p2p: A boolean value indicating if the socket option for Apple Peer-2-Peer should be set.

    """

    bind_addr = None
    sock = None

    if family == socket.AF_INET:
        bind_addr = get_ipv4_address(ifname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    elif family == socket.AF_INET6:
        bind_addr = get_ipv6_address(ifname)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        raise RuntimeError("Socket family not supported. family=%r" % family) from None

    # We need to set SO_REUSEADDR to allow the re-use of addresses by multiple processes.  This allows
    # more than one application to listen on multi-cast port addresses that are designated for specific
    # protocols.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # SO_REUSEADDR should be equivalent to SO_REUSEPORT for multicast UDP sockets
    # (p 731, "TCP/IP Illustrated, Volume 2").  Some BSD-derived systems require
    # SO_REUSEPORT to be specified explicitly.  Also, not all versions of Python
    # have SO_REUSEPORT available.
    # Catch OSError for when an OS is encountered that does not support SO_REUSEPORT support.
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError as os_err:
            if not os_err.errno == errno.ENOPROTOOPT:
                err_msg = "Error attempting to set socket option 'SO_REUSEPORT'. errno=%d" % os_err.errno
                raise RuntimeError(err_msg) from os_err

    # Set the IP protocol level socket opition IP_MULTICAST_IF which is used to bind
    # the socket to the address of a specific interface for OUTBOUND multi-cast traffic
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_addr))

    if ttl is not None:
        if family == socket.AF_INET:
            ttl = struct.pack(b'b', ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        else:
            sock.setsockopt(IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)

    if loop is not None:
        if family == socket.AF_INET:
            loop = struct.pack(b'b', loop)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
        else:
            sock.setsockopt(IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, loop)

    if apple_p2p:
        sock.setsockopt(socket.SOL_SOCKET, SO_RECV_ANYIF, 1)

    if timeout is not None:
        sock.settimeout(timeout)

    #sock.bind((bind_addr, port))

    # We also need to tell the Kernel to bind the INBOUND traffic destined for the multi-cast
    # group to the address for this interface, so we receive responses
    member_in = socket.inet_aton(multicast_addr) + socket.inet_aton(bind_addr)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, member_in)

    return sock
