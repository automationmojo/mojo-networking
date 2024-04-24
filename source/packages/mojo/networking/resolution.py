"""
.. module:: resolution
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains helper functions for resolving ip addresses.

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

from typing import List, Optional

import csv
import netifaces
import os

ARPING_RANGE_CMD = """/bin/bash -c 'for i in {1..254} ;do ping %s.$i -w 5 -c 1 > /dev/null 2>&1 & echo "%s.$i" & done; wait < <(jobs -p); echo Done' """

from mojo.networking.constants import CHARSET_IPV6_ADDR, REGEX_IPV4_COMPONENTS, REGEX_IPV6_COMPONENTS


def expand_ipv6_addr(addr: str) -> str:
    """
        Expand the wildcard '::' in an IPv6 address.
    """
    expanded = addr

    # If we see '::' expand it, there should be only one
    double_colon_count = addr.count("::")
    if double_colon_count > 1:
        errmsg = f"Invalid IPv6 address which contains more than one wildcard '::'.  addr={addr}"
        raise ValueError(errmsg)
    elif double_colon_count == 1:
        before_colons, after_colons = addr.split("::")

        if before_colons == "":
            after_parts = after_colons.split(":")
            after_parts_len = len(after_parts)
            fill_part_count = 8 - after_parts_len
            fill_comp = [ nc for nc in '0' * fill_part_count ]
            expanded = ":".join(fill_comp) + ":" + after_colons

        elif after_colons == "":
            before_parts = before_colons.split(":")
            before_parts_len = len(before_parts)
            fill_part_count = 8 - before_parts_len
            fill_comp = [ nc for nc in '0' * fill_part_count ]
            expanded = before_colons + ":" + ":".join(fill_comp)

        else:
            after_parts = after_colons.split(":")
            after_parts_len = len(after_parts)
            before_parts = before_colons.split(":")
            before_parts_len = len(before_parts)

            fill_part_count = 8 - (after_parts_len + before_parts_len)
            fill_comp = [ nc for nc in '0' * fill_part_count ]
            expanded = before_colons + ":" + ":".join(fill_comp) + ":" + after_colons

    return expanded


def get_arp_table(normalize_hwaddr: bool=False):
    arp_table = {}

    with open('/proc/net/arp') as aif:
        #'IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device'
        reader = csv.reader(aif, skipinitialspace=True, delimiter=' ')
        table_data_rows = [r for r in reader][1:]
        for ip, hwtype, flags, hwaddr, mask, ifname in table_data_rows:
            if normalize_hwaddr:
                hwaddr = hwaddr.replace(":", "").upper()
            iinfo = { hwaddr: {"hwaddr": hwaddr, "ip": ip, "ifname": ifname, "hwtype": hwtype, "flags": flags, "mask": mask }}
            arp_table.update(iinfo)

    return arp_table


def is_ipv4_address(candidate: str) -> bool:
    """
        Checks to see if 'candidate' is an ipv4 address.

        :param candidate: A string that is to be checked to see if it is a valid IPv4 address.

        :returns: A boolean indicating if an IP address is an IPv4 address
    """
    is_ipv4 = False

    # The regex will ensure that all the component characters are integer characters
    # and that we have the correct number of components.
    mobj = REGEX_IPV4_COMPONENTS.match(candidate)
    if mobj is not None:
        addr_components = [ v for v in mobj.groups() ]
        if len(addr_components) == 4:
            is_ipv4 = True
            for nc in addr_components:
                cval = int(nc)
                if cval < 0 or cval > 255:
                    is_ipv4 = False
                    break

    return is_ipv4


def is_ipv6_address(candidate: str) -> bool:
    """
        Checks to see if 'candidate' is an ipv6 address.

        :param candidate: A string that is to be checked to see if it is a valid IPv6 address.

        :returns: A boolean indicating if an IP address is an IPv6 address
    """
    is_ipv6 = False

    candidate = expand_ipv6_addr(candidate)
    
    # The regex will ensure that all the component characters are integer characters
    # and that we have the correct number of components.
    mobj = REGEX_IPV6_COMPONENTS.match(candidate)
    if mobj is not None:
        addr_components = [ v for v in mobj.groups() ]
        if len(addr_components) == 8:
            is_ipv6 = True
            for nc in addr_components:
                cval = int(nc, base=16)
                if cval < 0 or cval > 65535:
                    is_ipv6 = False
                    break

    return is_ipv6


def refresh_arp_table(exclude_interfaces: List=["lo"], include_interfaces: Optional[List[str]]=None):
    """
        ping -c 5 -b 10.x.x.255
    """

    interface_list = None
    if include_interfaces is not None:
        interface_list = include_interfaces
    else:
        interface_list = netifaces.interfaces()
    
    for ifname in interface_list:
        if ifname not in exclude_interfaces:
            address_info = netifaces.ifaddresses(ifname)
            if address_info is not None:

                # First look for IPv4 address information
                if netifaces.AF_INET in address_info:
                    addr_info = address_info[netifaces.AF_INET][0]
                    ifaddress = addr_info["addr"]
                    ifaddr_parts = ifaddress.split(".")
                    addr_prefix = ".".join(ifaddr_parts[:-1])
                    ping_cmd = ARPING_RANGE_CMD % (addr_prefix, addr_prefix)
                    os.system(ping_cmd)

    return


if __name__ == "__main__":
    refresh_arp_table()