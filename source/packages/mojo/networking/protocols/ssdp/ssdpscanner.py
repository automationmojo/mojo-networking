"""
.. module:: SsdpScanner
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module containing the :class:`MSearchRootDeviceProtocol` class and
               associated diagnostic.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>

"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []


from typing import Dict, Optional, Tuple

import logging
import re
import socket
import struct
import threading

from mojo.networking.multicast import create_multicast_socket


REGEX_NOTIFY_HEADER = re.compile("NOTIFY[ ]+[*/]+[ ]+HTTP/1")


logger = logging.getLogger()


class MSearchTargets:
    """
        MSearch target constants.
    """
    ROOTDEVICE = "upnp:rootdevice"
    ALL="ssdp:all"


class MSearchKeys:
    """
        MSearch dictionary or header keys that MSearch response data items are stored under.
    """
    CACHE_CONTROL = "CACHE-CONTROL"
    EXT = "EXT"
    LOCATION = "LOCATION"
    NTS = "NTS"
    SERVER = "SERVER"
    ST = "ST"
    USN = "USN"
    USN_DEV = "USN_DEV"
    USN_CLS = "USN_CLS"

    IP = "IP"
    ROUTES = "ROUTES"


class MSearchRouteKeys:
    """
        The dictionary keys that MSearch interface routing information is stored under.
    """
    IFNAME = "LOCAL_IFNAME"
    IP = "LOCAL_IP"


class SsdpProtocol:
    """
        SSDP Protocol constants.
    """
    MULTICAST_ADDRESS = '239.255.255.250'
    PORT = 1900

    HEADERS = {
        "ST": MSearchTargets.ROOTDEVICE,
        "Man": "ssdp:discover",
        "MX": "1"
    }

SSDP_IPV6_MULTICAST_ADDRESS_LINK_LOCAL="FF02::C"
SSDP_IPV6_MULTICAST_ADDRESS_SITE_LOCAL="FF05::C"
SSDP_IPV6_MULTICAST_ADDRESS_ORG_LOCAL="FF08::C"
SSDP_IPV6_MULTICAST_ADDRESS_GLOBAL_LOCAL="FF0E::"


def notify_parse_request(content: str) -> dict:
    """
        Takes in the content of the NOTIFY request and parses it into a
        python dictionary object.

        :param content: Notify request content as a string.

        :return: A python dictionary with key and values from the Notify request
    """
    content = content.decode('utf-8')

    resp_headers = None
    resp_body = None

    mobj = REGEX_NOTIFY_HEADER.search(content)
    if mobj is not None:
        header_content = None
        body_content = None

        if content.find("\r\n\r\n") > -1:
            header_content, body_content = content.split("\r\n\r\n", 1)
        elif content.find("\n\n") > -1:
            header_content, body_content = content.split("\n\n", 1)
        else:
            header_content = content

        resplines = header_content.splitlines(False)

        # Pop the NOTIFY header
        resplines.pop(0).strip()

        resp_headers = {}
        for nxtline in resplines:
            cidx = nxtline.find(":")
            if cidx > -1:
                key = nxtline[:cidx].upper()
                val = nxtline[cidx+1:].strip()
                resp_headers[key] = val

        if body_content is not None:
            resp_body = body_content

    return resp_headers, resp_body


def parse_ssdp_message(content: bytes) -> Dict[str, str]:
    """
        Takes in the content of the response of an MSEARCH request and parses it into a
        python dictionary object.

        :param content: MSearch response content as a bytes.

        :return: A python dictionary with key and values from the MSearch response
    """
    content = content.decode('utf-8')

    respinfo = None

    resplines = content.splitlines(False)
    if len(resplines) > 0:
        header = resplines.pop(0).strip()
        if header.startswith("M-SEARCH * HTTP/") or header.startswith("NOTIFY * HTTP/") or header.startswith("HTTP/"):
            respinfo = {}
            for nxtline in resplines:
                cidx = nxtline.find(":")
                if cidx > -1:
                    key = nxtline[:cidx].upper()
                    val = nxtline[cidx+1:].strip()
                    respinfo[key] = val

    return respinfo


class SsdpScanner:

    def __init__(self, multicast_address = SsdpProtocol.MULTICAST_ADDRESS, multicast_port = SsdpProtocol.PORT, 
                 ifname: str=None, discover_interval: int = 60, ttl: int=32):
        """
            :param ttl: The time to live for the multicast packet
                    0 = same host
                    1 = same subnet
                    32 = same site
                    64 = same region
                    128 = same continent
                    255 = unrestricted scope
        """
        self._multicast_address = multicast_address
        self._multicast_port = multicast_port
        self._ifname = ifname
        self._discover_interval = discover_interval
        self._ttl = ttl

        self._sock = None
        self._thread = None
        self._running = False

        return

    def start(self):
        
        if self._running:
            raise RuntimeError("SSDP Scanner is already running.")

        sgate = threading.Event()
        sgate.clear()
        
        self._thread = threading.Thread(target=self._response_thread_entry, name="mojo-ssdp-scanner", args=(sgate,), daemon=True)
        self._thread.start()

        sgate.wait()

        return

    def discover(self, st: str = MSearchTargets.ROOTDEVICE, custom_headers: Optional[Dict[str, str]] = None):

        if not self._running:
            raise RuntimeError("The SSDP Scanner must be running before a discovery can be triggered.  Call 'start'.")

        msearch_msg_lines = [
            b'M-SEARCH * HTTP/1.1',
            b'HOST: %s:%d' % (SsdpProtocol.MULTICAST_ADDRESS.encode("utf-8"), SsdpProtocol.PORT),
            b'ST: %s' % st.encode("utf-8"),
            b'MAN: "ssdp:discover"'
        ]

        if custom_headers is not None:
            for hname, hval in custom_headers.items():
                hname = hname.upper().encode("utf-8")
                msearch_msg_lines.append(b'%s: %s' % (hname, hval.encode("utf-8")))

        msearch_msg_lines.append(b'')
        msearch_msg_lines.append(b'')

        msearch_msg = b"\r\n".join(msearch_msg_lines)
        
        self._sock.sendto(msearch_msg, (self._multicast_address, self._multicast_port))
    
        return
    
    def process_msearch(self, resp_addr: Tuple[str, int], response: bytes):
        msg_info = parse_ssdp_message(response)
        print(f"M-SEARCH: from={resp_addr[0]} ST={msg_info["ST"]}\n")
        return

    def process_notify(self, resp_addr: Tuple[str, int], response: bytes):

        resp_info = parse_ssdp_message(response)

        if resp_info is not None:
            message_st = resp_info.get(MSearchKeys.ST, None)
        
            if MSearchKeys.USN in resp_info:
                usn_dev, usn_cls = resp_info[MSearchKeys.USN].split("::")
                usn_dev = usn_dev.lstrip("uuid:")
                if usn_cls == "upnp:rootdevice":
                    resp_info[MSearchKeys.USN_DEV] = usn_dev
                    resp_info[MSearchKeys.USN_CLS] = usn_cls

                    resp_info[MSearchKeys.IP] = resp_addr[0]

                    print(f"NOTIFY: from={resp_addr[0]}")
                    # DO Something with the notify message here
                else:
                    logger.debug("device_info didn't have a USN. %r" % resp_info)
        else:
            logger.debug("device_info was None.")
        
        return


    def process_reply(resp_addr: Tuple[str, int], response: bytes):
        print(f"REPLY: from={resp_addr[0]}")
        return


    def _response_thread_entry(self, sgate: threading.Event):

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        self._running = True

        sgate.set()

        while self._running:

            try:
                resp, addr = self._sock.recvfrom(1024)

                if resp.startswith(b"M-SEARCH * HTTP/"):
                    self.process_msearch(addr, resp)

                elif resp.startswith(b"NOTIFY * HTTP/"):
                    self.process_notify(addr, resp)

                elif resp.startswith(b"HTTP/"):
                    self.process_reply(addr, resp)
                
                else:
                    print(resp)

            except socket.timeout:
                pass

        return


if __name__ == "__main__":
    import time

    scanner = SsdpScanner()
    
    scanner.start()
    last_discovery = 0

    while True:
        now = time.time()
        discovery_interval = now - last_discovery
        if discovery_interval > 120:
            scanner.discover()
            last_discovery = time.time()
    
        print("Tick")
        time.sleep(5)
        print("Tock")
        time.sleep(5)
