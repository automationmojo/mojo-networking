
__author__ = "Myron Walker"
__copyright__ = "Copyright 2020, Myron W Walker"
__credits__ = []

from typing import Dict, List, Optional, Tuple, Type

import copy
import socket
import threading
import time
import weakref

from datetime import datetime, timedelta
from types import TracebackType

from mojo.errors.exceptions import SemanticError

from mojo.networking.multicast import create_multicast_socket
from mojo.networking.constants import MDNS_GROUP_ADDR, MDNS_GROUP_ADDR6, MDNS_PORT

from mojo.networking.protocols.dns.dnsconst import DNS_RECEIVE_BUFFER
from mojo.networking.protocols.dns.dnsflags import DEFAULT_DNS_FLAGS_QUERY
from mojo.networking.protocols.dns.dnsinboundmessage import DnsInboundMessage
from mojo.networking.protocols.dns.dnsoutboundmessage import DnsOutboundMessage
from mojo.networking.protocols.dns.dnsquestion import DnsQuestion
from mojo.networking.protocols.dns.dnsconst import DnsRecordType, DnsRecordClass


DEFAULT_SEARCH_TIMEOUT = 30.0
DEFAULT_RETRY_INTERVAL = 2.0


class MdnsServiceInfo:
    """
    """


class MdnsBrowseSearchWindow:
    """
    """

    def __init__(self, browser: "MdnsBrowseSearchWindow", id: int):
        """
            Constructs a :class:`MdnsBrowseWindow` object used to collect and store search results.
        """
        self._browser_ref = weakref.ref(browser)
        self._id = id
        self._span = None
        self._start = None
        self._stop = None
        return

    @property
    def browser(self) -> "MdnsBrowser":
        return self._browser_ref()
    
    @property
    def id(self) -> int:
        return self._id

    @property
    def span(self) -> float:
        return self._span

    def begin(self, span: float):    
        self._span = span
        self._start = datetime.now()
        self._stop = self._start + timedelta(seconds=self._span)
        return

    def wait_for_results(self, interval: float=DEFAULT_RETRY_INTERVAL):

        if self._start is None:
            errmsg = "You must call 'begin' before calling 'wait'"
            raise SemanticError(errmsg)

        while True:
        
            now = datetime.now()
            if now >= self._stop:
                # We always wait a specific amount of time, so its not an error to timeout, we just exit
                break

            time.sleep(interval)
    
        self.browser.close_search_window(self)

        return



class MdnsBrowser:

    def __init__(self, multicast_address = MDNS_GROUP_ADDR, multicast_port = MDNS_PORT, discover_interval: int = 60, ttl: int=32):
        
        self._multicast_address = multicast_address
        self._multicast_port = multicast_port
        self._discover_interval = discover_interval

        self._ttl = ttl

        self._lock = threading.Lock()

        self._running = False

        self._msearch_sock = None
        self._msearch_thread = None
        
        self._presence_sock = None
        self._presence_thread = None

        self._inactive_services = {}
        self._active_services = {}

        self._services_by_device = {}

        self._search_id = 1
        self._search_windows = {}

        self._known_service_classes = set()
        return
    
    @property
    def active_devices(self) -> Dict[str, Dict[str, str]]:
        rtnval = None

        self._lock.acquire()
        try:
            rtnval = copy.deepcopy(self._active_devices)
        finally:
            self._lock.release()

        return rtnval
    
    @property
    def inactive_devices(self) -> Dict[str, Dict[str, str]]:

        self._lock.acquire()
        try:
            rtnval = copy.deepcopy(self._inactive_devices)
        finally:
            self._lock.release()

        return rtnval

    @property
    def known_service_classes(self) -> List[str]:
        rtnval = list(self._known_service_classes)
        return rtnval

    def close_search_window(self, search_window: MdnsBrowseSearchWindow):
        del self._search_windows[search_window.id]
        return

    def start(self):
        
        if self._running:
            raise RuntimeError("SSDP Scanner is already running.")

        sgate = threading.Event()

        sgate.clear()
        
        self._presence_thread = threading.Thread(target=self._mdns_presence_thread_entry, name="mojo-mdns-presence", args=(sgate,), daemon=True)
        self._presence_thread.start()

        sgate.wait()

        sgate.clear()
        
        self._msearch_thread = threading.Thread(target=self._mdns_search_thread_entry, name="mojo-mdns-search", args=(sgate,), daemon=True)
        self._msearch_thread.start()

        sgate.wait()

        return

    def discover_service_classes(self, domain: str = "local", span: float = DEFAULT_SEARCH_TIMEOUT, custom_headers: Optional[Dict[str, str]] = None) -> MdnsBrowseSearchWindow:

        svc_type = f"_services._dns-sd._udp.{domain}"

        bsearch_window = self._create_search_window(span)
        
        questions = DnsQuestion(svc_type, DnsRecordType.PTR, DnsRecordClass.IN)

        mdns_msg = DnsOutboundMessage(DEFAULT_DNS_FLAGS_QUERY, id=bsearch_window.id)
        mdns_msg.add_question(questions)

        sock = self._get_search_socket()

        try:
            msg_packets = mdns_msg.packets()
            for packet in msg_packets:
                sock.sendto(packet, (self._multicast_address, self._multicast_port))

        except OSError as serr:
            # If we get an OSError while sending, our socket is likely invalid and we need
            # to force the socket to be re-freshed
            self._lock.acquire()
            try:
                if sock is not None:
                    sock.close()

                self._msearch_sock = None
            finally:
                self._lock.release()
            raise

        return bsearch_window

    def discover_services(self, service_classes: List[str] = None, domain: str = "local", custom_headers: Optional[Dict[str, str]] = None):

        if service_classes is None:
            service_classes = []

        if not self._running:
            raise RuntimeError("The SSDP Scanner must be running before a discovery can be triggered.  Call 'start'.")

        for svc_class in service_classes:
            questions = DnsQuestion(svc_class, DnsRecordType.PTR, DnsRecordClass.IN)

            mdns_msg = DnsOutboundMessage(DEFAULT_DNS_FLAGS_QUERY)
            mdns_msg.add_question(questions)
            
            sock = self._get_search_socket()

            try:
                msg_packets = mdns_msg.packets
                for packet in msg_packets:
                    sock.sendto(packet, (self._multicast_address, self._multicast_port))
            except OSError as serr:
                # If we get an OSError while sending, our socket is likely invalid and we need
                # to force the socket to be re-freshed
                self._lock.acquire()
                try:
                    if sock is not None:
                        sock.close()

                    self._msearch_sock = None
                finally:
                    self._lock.release()
                raise

        return

    def process_presence_message(self, from_endpoint: Tuple[str, int], msg_bytes: bytes):

        from_ip = from_endpoint[0]

        msg_in = DnsInboundMessage(msg_bytes, from_endpoint)
        msg_id = msg_in.id

        for dns_answer in msg_in.answers:

            rclass = dns_answer.rclass

            if rclass == DnsRecordClass.IN:
                akey = dns_answer.key
                aname = dns_answer.name
                rtype = dns_answer.rtype

                if rtype == DnsRecordType.PTR:
                    alias = dns_answer.alias
                    if aname == "_services._dns-sd._udp.local.":
                        self._known_service_classes.add(alias)

                    print(f"Presence: Answer ({from_endpoint}) id={msg_id} rtype={rtype.name} rclass={rclass.name} key={akey} name={aname} alias={alias}")
                else:
                    print(f"Presence: Answer ({from_endpoint}) id={msg_id} rtype={rtype.name} rclass={rclass.name} key={akey} name={aname}")

            else:
                print(f"Presence: Answer ({from_endpoint}) id={msg_id} rtype={rtype.name} rclass={rclass}")        

        return

    def process_search_response(self, from_endpoint: Tuple[str, int], msg_bytes: bytes):
        
        from_ip = from_endpoint[0]

        msg_resp = DnsInboundMessage(msg_bytes, source_endpoint=from_endpoint)

        msg_id = msg_resp.id

        for dns_answer in msg_resp.answers:

            rclass = dns_answer.rclass

            if rclass == DnsRecordClass.IN:
                akey = dns_answer.key
                aname = dns_answer.name
                rtype = dns_answer.rtype

                if rtype == DnsRecordType.PTR:
                    alias = dns_answer.alias
                    if aname == "_services._dns-sd._udp.local.":
                        self._known_service_classes.add(alias)

                    print(f"Search: Answer ({from_endpoint}) id={msg_id} rtype={rtype.name} rclass={rclass.name} key={akey} name={aname} alias={alias}")
                else:
                    print(f"Search: Answer ({from_endpoint}) id={msg_id} rtype={rtype.name} rclass={rclass.name} key={akey} name={aname}")

            else:
                print(f"Search: Answer ({from_endpoint}) id={msg_id} rtype={rtype.name} rclass={rclass}")

        return

    def service_updated(self, context: str, status: str, service_info: MdnsServiceInfo):

        print(f"UPDATE SERVICE: context={context} status={status}")

        return

    def _create_search_window(self, span: float) -> MdnsBrowseSearchWindow:
        
        bsearch_id = self._next_search_id() 
        bwindow = MdnsBrowseSearchWindow(self, bsearch_id)
        self._search_windows[bsearch_id] = bwindow
        bwindow.begin(span)

        return bwindow

    def _get_presence_socket(self) -> socket.socket:

        sock = None

        self._lock.acquire()
        try:
            if self._presence_sock is None:
                self._presence_sock: socket.socket = create_multicast_socket(self._multicast_address, self._multicast_port, family=socket.AF_INET, ttl=self._ttl)
            
            sock = self._presence_sock
        finally:
            self._lock.release()
            
        return sock

    def _get_search_socket(self) -> socket.socket:

        sock = None

        self._lock.acquire()
        try:
            if self._msearch_sock is None:
                self._msearch_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

            sock = self._msearch_sock
        finally:
            self._lock.release()
            
        return sock

    def _mdns_presence_thread_entry(self, sgate: threading.Event):

        self._running = True

        self._presence_sock: socket.socket = create_multicast_socket(self._multicast_address, self._multicast_port, family=socket.AF_INET, ttl=self._ttl)
        
        sgate.set()

        while self._running:

            sock = self._get_presence_socket()

            try:
                resp, addr = sock.recvfrom(DNS_RECEIVE_BUFFER)

                self.process_presence_message(addr, resp)
            except socket.timeout:
                pass

            except:
                self._lock.acquire()
                try:
                    if sock is not None:
                        sock.close()

                    self._presence_sock = None
                finally:
                    self._lock.release()

        return

    def _mdns_search_thread_entry(self, sgate: threading.Event):

        self._running = True

        self._msearch_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        sgate.set()

        while self._running:

            sock = self._get_search_socket()

            try:
                resp, addr = sock.recvfrom(DNS_RECEIVE_BUFFER)

                self.process_search_response(addr, resp)
                
            except socket.timeout:
                pass

            except OSError:
                self._lock.acquire()
                try:
                    if sock is not None:
                        sock.close()

                    self._msearch_sock = None
                finally:
                    self._lock.release()

        return

    def _next_search_id(self) -> int:
        search_id = self._search_id
        self._search_id += 1
        return search_id


if __name__ == "__main__":

    browser = MdnsBrowser()
    browser.start()

    bsearch_window = browser.discover_service_classes()
    bsearch_window.wait_for_results()

    service_classes = browser.known_service_classes
    service_classes.append("_bose-passport.tcp")

    browser.discover_services(service_classes)

    while True:
        print("blah")
        time.sleep(2)

