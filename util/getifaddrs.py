#! /usr/bin/env python3

"""  getifaddrs - Read and print interface and address information

     Based on https://gist.github.com/provegard/1536682, which was
     based on getifaddrs.py from pydlnadms http://code.google.com/p/pydlnadms/
     Tested on Linux and OS X only!

     Ignacio Martinez igmartin@movistar.es
     Jan 2023
"""

########################################
#
# Imports and basic symbol definitions
#
########################################
# Tested only on MacOS and linux
#
import sys
import os
from os import strerror

from socket import AF_UNSPEC, AF_UNIX, AF_INET, AF_INET6, SOCK_DGRAM
from util.address import (Address, IPv4Address, IPv6Address, LinkLayerAddress,
                     SCP_INTLOCAL, SCP_LINKLOCAL, SCP_SITELOCAL, SCP_GLOBAL,
                     struct_sockaddr, struct_sockaddr_in, struct_sockaddr_in6,
                     get_address,)
from util.custlogging import get_logger, ERROR, WARNING

logger = get_logger(__name__, WARNING)

ALLOWED_OSES = ('darwin', 'linux', 'linux2', 'linux3')
if sys.platform not in ALLOWED_OSES:
    logger.error("platform %s is not supported. Exiting", sys.platform)
    sys.exit(1)

IS_DARWIN = sys.platform == 'darwin'
IS_LINUX  = sys.platform.startswith('linux')

# common symbol for L2 address family
if IS_DARWIN:
    from socket import AF_LINK
    AF_LOCAL_L2 = AF_LINK
elif IS_LINUX:
    from socket import AF_PACKET
    AF_LOCAL_L2 = AF_PACKET

# from sys/socket.h
AF_LOCAL = AF_UNIX
AF_MAX   = 42

from ctypes import (
    CDLL,
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_char, c_short, c_int, c_uint,
    c_void_p, c_char_p,
    c_uint8, c_uint16
)
from ctypes.util import find_library

libc = CDLL(find_library('c'), use_errno=True)

######################################################################
#
# Symbols and mappings
#
######################
# Some ioctl codes
#
if IS_DARWIN:
    SIOCGIFMETRIC = 0xC0206917
    SIOCGIFMTU    = 0xC0206933
    SIOCGIFCAP    = 0xC020695B
    SIOCGIFPHYS   = 0xC0206935
    SIOCGIFSTATUS = 0xC331693D
else:
    SIOCGIFMETRIC = 0x0000891D
    SIOCGIFMTU    = 0x00008921
    SIOCGIFTXQLEN = 0x00008942

# Ethernet hardware types (MacOS)
#
IFT_ETHER  = 0x06
IFT_LOOP   = 0x18
IFT_L2VLAN = 0x87
IFT_BRIDGE = 0xd1
#
# (linux)
#
ARPHRD_ETHER    = 1
ARPHRD_LOOPBACK = 772

# interface flags
#
IFF_UP          = 0x0001
IFF_BROADCAST   = 0x0002
IFF_LOOPBACK    = 0x0008
IFF_POINTOPOINT = 0x0010
if IS_DARWIN:
    IFF_MULTICAST   = 0x8000
elif IS_LINUX:
    IFF_MULTICAST   = 0x1000

# IPv6 scope
#
SCP_MIN          = 0x00
SCP_ALL          = 0x10

# address family mappings
#
familymap = { AF_UNSPEC:   "all",
              AF_LOCAL_L2: "link",
              AF_INET:     "inet",
              AF_INET6:    "inet6",
            }

HEXDIGITS = "0123456789abcdef"

##################################
# macro-style short functions
#
def family_match(fam, reqfam):
    """ return True if 'fam' matches the expected family
        or the latter is 'all families' """

    return reqfam in (fam, AF_UNSPEC)

def scope_match(scp, reqscp):
    """ return True if 'scp' matches the expected scope
        or the latter is 'all scopes' """

    return reqscp in (scp, SCP_ALL)

def islayer2(fam):
    """ return True if address family is link layer """

    return fam == AF_LOCAL_L2

def isether(hwt):
    """ return True if the link is Ethernet """

    return ((IS_DARWIN and hwt in (IFT_ETHER, IFT_L2VLAN, IFT_BRIDGE)) or
            (IS_LINUX  and hwt == ARPHRD_ETHER))

def isloop(hwt):
    """ return True is the link is loopback """

    return ((IS_DARWIN and hwt == IFT_LOOP) or
            (IS_LINUX  and hwt == ARPHRD_LOOPBACK))

def revmap(dmap, val):
    """ return the key for value 'val' in dictionary 'dmap'
        None if no value found """

    return (list(dmap)[list(dmap.values()).index(val)]
               if val in dmap.values() else None)

#
# Assume ascii encoding for interface names
#
GETIFADDRS_ENCODING = 'ascii'

# interface name max size for structure ifreq and sizeof(struct ifreq)
#
IFNAMSIZ     = 16
SIZEOF_IFREQ = 32

#####################################################
#
#        C data structures
#
# sockaddr structures for hardware addresses
# MacOS uses "struct sdl" whereas "struct ll" describes linux hw addresses
#
if IS_DARWIN:
    class struct_sockaddr_dl(Structure):
        _fields_ = [
            ('sdl_len',     c_uint8),
            ('sdl_family',  c_uint8),
            ('sdl_index',   c_uint16),
            ('sdl_type',    c_uint8),
            ('sdl_nlen',    c_uint8),
            ('sdl_alen',    c_uint8),
            ('sdl_slen',    c_uint8),
            ('sdl_data',    c_uint8 * 256),]

if IS_LINUX:
    class struct_sockaddr_ll(Structure):
        _fields_ = [
            ('sll_family',   c_uint16),
            ('sll_protocol', c_uint16),
            ('sll_ifindex',  c_int),
            ('sll_hatype',   c_uint16),
            ('sll_pkttype',  c_uint8),
            ('sll_halen',    c_uint8),
            ('sll_data',     c_uint8 * 8),]

# Simplified version of "struct ifaddr"
# Use in linux the same semantics for the field 'ifa_dstaddr' as in MacOS
#   if interface is broadcast capable, field contains the broadcast address
#   otherwise, if interface is point-to-point, field contains
#   the destination address of the link
#
class struct_ifaddrs(Structure):
    pass

struct_ifaddrs._fields_ = [
    ('ifa_next',    POINTER(struct_ifaddrs)),
    ('ifa_name',    c_char_p),
    ('ifa_flags',   c_uint),
    ('ifa_addr',    POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_dstaddr', POINTER(struct_sockaddr)),
    ('ifa_data',    c_void_p),]

# Structure ifreq for getting interface information with ioctl
# Simplified to include relevant fields only
# Added padding up to the original union size
#
class union_ifr_ifru(Union):
    _fields_ = [
        ('ifru_addr',      struct_sockaddr),
        ('ifru_dstaddr',   struct_sockaddr),
        ('ifru_broadaddr', struct_sockaddr),
        ('ifru_flags',     c_short),
        ('ifru_metric',    c_int),
        ('ifru_mtu',       c_int),
        ('ifru_phys',      c_int),
        ('ifru_media',     c_int),
        ('ifru_intval',    c_int),
        ('ifru_cap',       c_int * 2),
        ('ifru_pad',       c_char * (SIZEOF_IFREQ-IFNAMSIZ)),]

class struct_ifreq(Structure):
    _fields_ = [
        ('ifr_name',    c_char * IFNAMSIZ),
        ('ifr_ifru',    union_ifr_ifru),]

#############################################################################
#
# module defined classes for abstracting network interfaces and its addresses
#
class NetworkInterface(object):
    """ A placeholder for interface related information including addresses """

    def __init__(self, name):

        self.name    = name
        self.flags   = 0
        self.eflags  = 0
        self.metric  = 0
        self.mtu     = 0
        self.options = 0
        self.index   = 0
        self.phys    = 0
        self.hwtype  = None

        self.txqlen  = 0            # linux only

        self.addresses  = []
        self.groups     = []

        self.querier    = 0
        self.mflags     = 0

    def is_broadcast(self):

        return self.flags & IFF_BROADCAST

    def is_pointopoint(self):

        return self.flags & IFF_POINTOPOINT

    def getaddress(self, ifa, psa):
        """ read and save an address according to its family
            acting as a NetworkInterface address factory """

        if not ifa or not psa:
            return None, None

        encname  = ifa.ifa_name
        sockaddr = ifa.ifa_addr
        flags    = ifa.ifa_flags

        name = encname.decode(GETIFADDRS_ENCODING)
        fam  = sockaddr.contents.sa_family

        # in MacOS, avoid spurious destination addresses
        # for point-to-point interfaces 
        # inactive utunx interfaces point to an empty sockaddr
        # for destination addresses
        if psa.contents.sa_family != fam:
            return None, None

        addr      = None
        interface = self
        if fam == AF_INET:
            sin  = cast(psa, POINTER(struct_sockaddr_in)).contents
            addr = InterfaceIPv4Address(bytes(sin.sin_addr), interface)

        elif fam == AF_INET6:
            sin6 = cast(psa, POINTER(struct_sockaddr_in6)).contents
            addr = InterfaceIPv6Address(bytes(sin6.sin6_addr), interface,
                                        sin6.sin6_scope_id)

        elif fam == AF_LOCAL_L2:
            self.flags  = flags & 0x0000FFFF
            self.eflags = flags & 0xFFFF0000
            # get interface metric, mtu, ...
            self.getoptions(encname)
            #
            if IS_DARWIN:
                sdl  = cast(psa, POINTER(struct_sockaddr_dl)).contents
                addr = InterfaceLinkLayerAddress(
                   bytes(sdl.sdl_data[sdl.sdl_nlen:sdl.sdl_nlen+sdl.sdl_alen]),
                   interface)
                self.hwtype = sdl.sdl_type 
                self.index  = sdl.sdl_index
            if IS_LINUX:
                sll  = cast(psa, POINTER(struct_sockaddr_ll)).contents
                addr = InterfaceLinkLayerAddress(
                   bytes(sll.sll_data[:sll.sll_halen]),
                   interface)
                self.hwtype = sll.sll_hatype
                self.index  = sll.sll_ifindex

        # add your favourite family here
        #
           
        return addr, fam

    def getoptions(self, name):
        """ libc based ioctl calls to obtain some additional attributes
            note that requests with highest bit set must be cast to avoid
            being interpreted as signed """ 

        s = libc.socket(AF_LOCAL, SOCK_DGRAM, 0)
        if s < 0:
            err = get_errno()
            logger.error("socket error (%d): %s", err, os.strerror(err))
            return err

        ifr  = struct_ifreq()
        ifrp = pointer(ifr)

        ifr.ifr_name = name

        if libc.ioctl(s, c_uint(SIOCGIFMETRIC), ifrp) == 0:
            self.metric = ifr.ifr_ifru.ifru_metric

        if libc.ioctl(s, c_uint(SIOCGIFMTU), ifrp) == 0:
            self.mtu = ifr.ifr_ifru.ifru_mtu

        if IS_DARWIN:
            if libc.ioctl(s, c_uint(SIOCGIFCAP), ifrp) == 0:
                self.options = ifr.ifr_ifru.ifru_cap[1]

            if libc.ioctl(s, c_uint(SIOCGIFPHYS), ifrp) == 0:
                self.phys = ifr.ifr_ifru.ifru_phys

        if IS_LINUX:
            if libc.ioctl(s, c_uint(SIOCGIFTXQLEN), ifrp) == 0:
                self.txqlen = ifr.ifr_ifru.ifru_intval

        libc.close(s)

        return 0

    def __str__(self):
        """ interface printout """

        fmt = ("%s: flags=%x, eflags=%x, metric=%d, "
               "mtu=%d, options=%x, index=%d, hwtype=%d" % (
                   self.name, self.flags, self.eflags, self.metric,
                   self.mtu, self.options, self.index, self.hwtype))

        if IS_LINUX:
            fmt += ", txqlen=%d" % self.txqlen

        for addr in self.addresses:
            if addr.family == AF_LOCAL_L2 and addr.printable:
                fmt += "\n\tether %s" % addr.printfulladdress()
        for addr in self.addresses:
            if addr.family == AF_INET:
                fmt += "\n\tinet %s" % addr.printfulladdress()
        for addr in self.addresses:
            if addr.family == AF_INET6:
                fmt += "\n\tinet6 %s" % addr.printfulladdress()
                
        return fmt

class InterfaceIPv4Address(IPv4Address):
    """ IP address family subclass """

    def __init__(self, addr, iface):

        super().__init__(addr, host="")

        self.interface   = iface

        self.netmask     = None
        self.broadcast   = None
        self.destination = None
        self.prefixlen   = None     # CIDR mask
        
    def getprefix(self, netmask):
        """ get the prefix length of an address by examining its netmask """

        prefixlen = 0

        if netmask:
            mask = 1 << 31
            i = int.from_bytes(netmask.in_addr, 'big')
            while i & mask:
                prefixlen += 1
                i <<= 1

        return prefixlen

    def getmaskdest(self, maddr, daddr, interface):
        """ get the netmask address as well as the broadcast/destination
            depending on media """

        # network mask
        if maddr:
            self.netmask   = maddr
            self.prefixlen = self.getprefix(self.netmask)

        # broadcast or destination address
        if daddr:
            if interface.is_broadcast():
                self.broadcast = daddr
            elif interface.is_pointopoint():
                self.destination = daddr

        return 0

    def printaddress(self, *args):
        """ obtain a printable version of an IPv4 address """

        return self.printable
        
    def printfulladdress(self, *args):

        addrout = self.printaddress()
        if self.netmask:
            addrout += " netmask %s" % self.netmask.printaddress()
        if self.broadcast:
            addrout += " broadcast %s" % self.broadcast.printaddress()
        elif self.destination:
            addrout += " destination %s" % self.destination.printaddress()

        return addrout

class InterfaceIPv6Address(IPv6Address):
    """ IP version 6 address family subclass """

    def __init__(self, addr, iface, scope_id):

        super().__init__(addr, host="", scope_id=scope_id)

        self.interface   = iface
        self.scope_id    = scope_id

        self.netmask     = None
        self.destination = None
        self.prefixlen   = None

    def getprefix(self, netmask):
        """ get the prefix length of an address by examining its netmask """

        prefixlen = 0

        if netmask:
            mask = 1 << 127
            i = int.from_bytes(netmask.in_addr, 'big')
            while i & mask:
                prefixlen += 1
                i <<= 1

        return prefixlen

    def getmaskdest(self, maddr, daddr, interface):
        """ get the netmask address as well as the broadcast/destination
            depending on media """

        # network mask
        if maddr:
            self.netmask   = maddr
            self.prefixlen = self.getprefix(self.netmask)

        # destination address
        if daddr and interface.is_pointopoint():
            self.destination = daddr

        return 0

    def printaddress(self, printzone=True):
        """ obtain a printable version of a unicast IPv6 address
            with or without the 'zone id' """

        printable = self.original

        if printzone:
            printable = self.printable

        return printable

    def printfulladdress(self, printzone=True):
        """ printable version of address with or without 'zone id'
            for non-global addresses """

        addrout = self.printaddress(printzone)
        addrout += " prefixlen %d" % self.prefixlen
        if self.destination and self.interface.is_pointopoint():
            addrout += " destination %s" % self.destination.printaddress()
        if self.scope_id and self.scope not in (SCP_GLOBAL, SCP_INTLOCAL):
            addrout += " scopeid 0x%x" % self.scope_id
        return addrout

    def __str__(self):

        return self.printaddress()

class InterfaceLinkLayerAddress(LinkLayerAddress):
    """ Link Layer address family class """

    def __init__(self, addr, iface):

        super().__init__(addr)

        self.interface = iface

    def printaddress(self, *args):
        """ obtain a printable version of the link layer address """

        return self.printable
        
    def printfulladdress(self, *args):

        return self.printaddress()

    def __str__(self):

        return self.printaddress()

#######################################################
#
def ifap_iter(ifap):
    """ generator to iterate over interfaces """

    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents

def get_network_interfaces(ifname=None,
                           reqfamily=AF_UNSPEC,
                           reqscope=SCP_ALL):
    """ walk through all network interfaces gathering address information
        filters available for interface names, address families
        and address scope """

    ifap = POINTER(struct_ifaddrs)()
    if libc.getifaddrs(pointer(ifap)) != 0:
        logger.error("getifaddrs: %s", os.strerror(get_errno()))
        raise OSError(get_errno(), os.strerror(get_errno()))

    try:
        interfaces = {}
        for ifa in ifap_iter(ifap):

            # get interface name creating a new interface instance if needed 
            #
            name = ifa.ifa_name.decode(GETIFADDRS_ENCODING)
            if ifname and (name != ifname):
                continue

            if name not in interfaces:
                interfaces[name] = NetworkInterface(name)
            interface = interfaces[name]

            sockaddr     = ifa.ifa_addr
            masksockaddr = ifa.ifa_netmask
            destsockaddr = ifa.ifa_dstaddr
            flags        = ifa.ifa_flags

            # hw address contains important interface information
            # need to get the info before checking address family
            #
            addr, fam = interface.getaddress(ifa, sockaddr)

            if not family_match(fam, reqfamily):
                del addr
                continue

            # done with link layer. Now get netmask and
            # broadcast/destination addresses
            # destination addresses are non-null but meaningless
            # for loopback and tunnel interfaces
            # in linux, we must use the parent address family
            #
            if fam in (AF_INET, AF_INET6):
                maskaddr, _ = interface.getaddress(ifa, masksockaddr)
                destaddr, _ = interface.getaddress(ifa, destsockaddr)

                addr.getmaskdest(maskaddr, destaddr, interface)

            # and the address scope (IPv6)
            #
            if fam == AF_INET6:
                if not scope_match(addr.scope, reqscope):
                    del addr
                    continue

            interface.addresses.append(addr)

        return interfaces.values()
    finally:
        libc.freeifaddrs(ifap)

######################################################################
#
# public constants and methods
#

GIA_AF_UNSPEC  = AF_UNSPEC
GIA_AF_LINK    = AF_LOCAL_L2
GIA_AF_INET    = AF_INET
GIA_AF_INET6   = AF_INET6

GIA_SCP_MIN    = SCP_MIN
GIA_SCP_ALL    = SCP_ALL
GIA_SCP_HOST   = SCP_INTLOCAL       # node-local (loopback)
GIA_SCP_LINK   = SCP_LINKLOCAL      # link-local
GIA_SCP_SITE   = SCP_SITELOCAL      # site-local (deprecated)
GIA_SCP_GLOBAL = SCP_GLOBAL         # global

def get_interface_names(ifiter=None) -> tuple:
    """ return a tuple with the names of all available interface """

    if not ifiter:
        ifiter = get_network_interfaces()

    return tuple([iface.name for iface in ifiter])

def get_interface_by_id(ifname: str|int, ifiter=None) -> NetworkInterface:
    """ get an interface object from its name/index """

    if not ifname:
        return None

    if not ifiter:
        ifiter = get_network_interfaces()

    for iface in ifiter:
        if isinstance(ifname, int) and ifname == iface.index:
            return iface
        elif isinstance(ifname, str):
            if ifname == iface.name:
                return iface
            if ifname.isdecimal() and int(ifname) == iface.index:
                return iface

    return None

def get_interface_by_addr(ifname: str|bytes|bytearray,
                          family: int=AF_UNSPEC, 
                          ifiter=None) -> NetworkInterface:
    """ get an interface object from one of its addresses/in_addrs """

    if not ifname:
        return None

    if not ifiter:
        ifiter = get_network_interfaces()

    if isinstance(ifname, str):
        addr = get_address(ifname, 0, family, type=SOCK_DGRAM)
        if not addr:
            return None
        ifaddr = addr.in_addr
    elif isinstance(ifname, bytes|bytearray):
        ifaddr = ifname
    else:
        return None

    addr = find_interface_address(ifaddr, ifiter=ifiter)
    if addr:
        return addr.interface

    return None

def get_interface(ifname: str|int|bytes,
                  family: int=AF_UNSPEC,
                  ifiter=None) -> NetworkInterface:
    """ get the interface object for the interface name selected """

    if not ifname:
        return None

    if not ifiter:
        ifiter = get_network_interfaces()

    ifc = get_interface_by_id(ifname, ifiter)
    if not ifc:
        ifc = get_interface_by_addr(ifname, family, ifiter)
    
    return ifc

def get_interface_index(iface: str|int|bytes,
                        family=GIA_AF_UNSPEC,
                        ifiter=None) -> int:
    """ obtain the index of the interface 'iface'. If iface is an address,
        try to resolve to the interface in which the address is configured """

    # default interface
    ifindex = 0

    # iface is None, "" or 0
    if not iface:
        return ifindex

    # INADDR_ANY/INADDR6_ANY
    if iface == "0.0.0.0" or iface == "::":
        return ifindex
    if (iface == b'\x00\x00\x00\x00' or iface ==
          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
        return ifindex

    if not ifiter:
        ifiter = get_network_interfaces()

    ifc = get_interface(iface, ifiter=ifiter)
    if ifc:
        ifindex = ifc.index
    else:
        ifaddr = find_interface_address(iface, family, ifiter=ifiter)
        if ifaddr:
            ifindex = ifaddr.interface.index

    return ifindex

def get_interface_addresses(ifname: str|int,
                            fam:    int=GIA_AF_UNSPEC,
                            scope:  int=GIA_SCP_ALL) -> list[Address]:
    """ return a list of addresses for the families and scopes selected
        return None if there is no interface with such a name
        return a (possibly empty) list of addresses otherwise """

    iface = get_interface(ifname)
    if not iface:
        return None

    addrlist = []
    for addr in iface.addresses:
        if not family_match(addr.family, fam):
            continue
        if addr.family == GIA_AF_INET6 and not scope_match(addr.scope, scope):
            continue
        addrlist.append(addr)
               
    return addrlist

def get_interface_address(ifname: str|int,
                          fam:    int=GIA_AF_LINK,
                          scope:  int=GIA_SCP_ALL) -> Address:
    """ return a single address for the interface name and family selected
        if all families are selected, return the hardware address if any
        if family is inet6, an address, if any, with the required scope
        is returned otherwise (all scopes selected), the address with
        the highest scope is returned """

    # Same systems have subinterfaces, which look like
    # normal interfaces to this method
    # Other systems have the primary/secondary ... address concept.
    # We assume here that the interface's primary address
    # is the one that comes first
    #
    addrlist = get_interface_addresses(ifname, fam, scope)

    if not addrlist:
        return None

    if fam == GIA_AF_INET6:
        curscope = GIA_SCP_MIN
        for addr in addrlist[:]:
            if addr.scope == scope:
                return addr
            if addr.scope > curscope:
                curscope = addr.scope
                addrlist[0] = addr
        if not scope_match(addrlist[0], scope):
            return None

    return addrlist[0]

def find_interface_address(addr:   str|bytes|bytearray,
                           fam:    int=GIA_AF_UNSPEC,
                           ifname: str=None,
                           ifiter=None) -> Address:
    """ use a string representation of an address to search
        for a matching address object.
        Lookup can be restricted to an interface and/or a family
        important: address scope is encoded in the address itself """

    if not ifiter:
        ifiter = get_network_interfaces(ifname, fam)

    if isinstance(addr, str):
        address = get_address(addr, family=fam)
        if not address:
            return None
        # if address is IPv6 and carries 'zone_id', verify interface is valid
        if address.family == GIA_AF_INET6 and address.zone_id:
            iface = get_interface_by_id(address.zone_id, ifiter=ifiter)
            if not iface:
                logger.error("Invalid zone_id in address '%s'", addr)
                return None
            if ifname and iface.name != ifname:
                return None
            ifname = iface.name
        ifaddr  = address.in_addr
    elif isinstance(addr, bytes|bytearray):
        ifaddr = addr
    else:
        return None

    for iface in ifiter:
        for address in iface.addresses:
            if ifaddr == address.in_addr:
                return address 

    return None

def print_interface_addresses(ifname:  str,
                              fam:     int=GIA_AF_UNSPEC,
                              scope:   int=GIA_SCP_ALL,
                              fullfmt: bool=False) -> list[str]:
    """ print the list of addresses configured in the interface
        for the address familiy and the address scope selected """

    addrlist = get_interface_addresses(ifname, fam, scope)
    if addrlist is None:
        return []

    if fullfmt:
        return [addr.printfulladdress() for addr in addrlist]

    return [addr.printaddress() for addr in addrlist]

def print_interface_address(ifname:  str,
                            fam:     int=GIA_AF_LINK,
                            scope:   int=GIA_SCP_ALL,
                            fullfmt: bool=False,
                            zone:    bool=True) -> str:
    """ return a single address for the interface and family selected
        if no address family is selected, the link layer address is returned
        if the interface has multiple IPv6 addresses and no scope is selected,
        the address with the highest scope is returned
        if zone is False, this prevents adding '%zone_id' to
        IPV6 local-link addresses """

    addr = get_interface_address(ifname, fam, scope)
    if not addr:
        return ""

    if fullfmt:
        return addr.printfulladdress(zone)

    return addr.printaddress(zone)

__all__ = ["GIA_AF_UNSPEC", "GIA_AF_LINK", "GIA_AF_INET", "GIA_AF_INET6",
           "GIA_SCP_ALL", "GIA_SCP_HOST", "GIA_SCP_LINK", "GIA_SCP_GLOBAL",
           "get_network_interfaces",
           "get_interface", "get_interface_names",
           "get_interface_by_id", "get_interface_by_addr",
           "find_interface_address",
           "get_interface_address", "get_interface_addresses",
           "print_interface_address", "print_interface_addresses"]

if __name__ == "__main__":
    [print(str(ni)) for ni in get_network_interfaces()]
