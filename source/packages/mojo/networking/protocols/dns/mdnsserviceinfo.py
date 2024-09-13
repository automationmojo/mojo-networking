

import os
import socket

class MdnsServiceInfo:

    def __init__(self):
        self._addresses = []
        self._host_ttl = None
        self._other_ttl = None
        self._interface_index = None
        self._key = None
        self._port = None
        self._priority = None
        self._server = None
        self._properties = {}
        self._server = None
        self._server_key = None
        self._svc_name = None
        self._svc_type = None
        self._text = None
        self._weight = None
        return

    @property
    def addresses(self):
        return self._addresses

    @property
    def first_ipv4_address(self):
        fipv4_addr = None

        for addr in self._addresses:
            if len(addr) == 4: 
                fipv4_addr = socket.inet_ntoa(addr)
                break

        return fipv4_addr

    @property
    def host_ttl(self):
        return self._host_ttl

    @property
    def interface_index(self):
        return self._interface_index

    @property
    def key(self):
        return self._key
    
    @property
    def other_ttl(self):
        return self._other_ttl
    
    @property
    def port(self):
        return self._port

    @property
    def priority(self):
        return self._priority
    
    @property
    def properties(self):
        return self._properties
    
    @property
    def server(self):
        return self._server
    
    @property
    def server_key(self):
        return self._server_key

    @property
    def svc_name(self):
        return self._name
    
    @property
    def svc_type(self):
        return self._type

    @property
    def text(self):
        return self._text
    
    @property
    def weight(self):
        return self._weight


    def detail_lines(self):

        str_lines = [
            "svc_name: {}".format(self._svc_name),
            "svc_type: {}".format(self._svc_type),
            "ipv4_addr: {}".format(self.first_ipv4_address),
            "properties"
        ]

        svc_props = self.properties

        svc_prop_keys = [k for k in svc_props]
        svc_prop_keys.sort()

        for key in svc_prop_keys:
            val = svc_props[key]
            if isinstance(val, bytes):
                str_lines.append("    {}: {}".format(key, repr(val.decode())))
            else:
                str_lines.append("    {}: {}".format(key, repr(val)))

        return str_lines

    def __str__(self):
        
        str_lines = self.detail_lines()
        strval = os.linesep.join(str_lines)

        return strval
