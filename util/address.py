""" this module contains tools for network address manipulation """

# system imports
import sys
from socket import (AF_UNSPEC, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM,
                    AI_PASSIVE, AI_CANONNAME, AI_V4MAPPED, AI_NUMERICHOST,
                    AI_NUMERICSERV, NI_NUMERICHOST, NI_NUMERICSERV,
                    getaddrinfo, getnameinfo, inet_ntop, inet_pton,
                    gaierror,)
from ctypes import (Structure, c_char, c_byte, c_ushort,
                               c_uint8, c_uint16, c_uint32, c_int64,)

# local imports
from util.custlogging import get_logger, ERROR, WARNING

#################
# Constants
#

# MAC address syntax
#
HEXDIGITS = "0123456789abcdef"

# Text representation of INADDR_ANY and UNSPECIFIED addresses
#
INADDR_ANY  = bytes(4)
INADDR6_ANY = bytes(16)

T_INADDR_ANY  = "0.0.0.0"
T_INADDR6_ANY = "::"

# Scope of IPv6 multicast addresses
#
SCP_INTLOCAL     = 0x01         # + unicast loopback
SCP_LINKLOCAL    = 0x02         # + unicast link local
SCP_REALMLOCAL   = 0x03
SCP_ADMINLOCAL   = 0x04
SCP_SITELOCAL    = 0x05         # + unicast site local (deprecated)
SCP_ORGANIZATION = 0x08
SCP_GLOBAL       = 0x0e         # + unicat global addresses

IS_DARWIN = sys.platform == 'darwin'
IS_LINUX  = sys.platform.startswith('linux')

# common symbol for L2 address family
if IS_DARWIN:
    from socket import AF_LINK
    AF_LOCAL_L2 = AF_LINK
elif IS_LINUX:
    from socket import AF_PACKET
    AF_LOCAL_L2 = AF_PACKET

family_map = {AF_LOCAL_L2: "link layer", AF_INET: "IPv4", AF_INET6: "IPv6"}

logger = get_logger(__name__, WARNING)

###################################################
#
#            C data structures
#
class struct_in_addr(Structure):
    _fields_ = [
        ('s_addr',        c_uint32),]

class struct_in6_addr(Structure):
    _fields_ = [
        ('s6_addr',       c_uint8 * 16),]

# generic sockaddr structure
#
class struct_sockaddr(Structure):
    if IS_DARWIN:
        _fields_ = [
            ('sa_len',    c_uint8),
            ('sa_family', c_uint8),
            ('sa_data',   c_byte * 14),]
    elif IS_LINUX:
        _fields_ = [
            ('sa_family', c_ushort),
            ('sa_data',   c_byte * 14),]

# sockaddr structures for IPv4 and IPv6 addresses
#
class struct_sockaddr_in(Structure):
    if IS_DARWIN:
        _fields_ = [
            ('sin_len',    c_uint8),
            ('sin_family', c_uint8),
            ('sin_port',   c_uint16),
            ('sin_addr',   c_byte * 4),
            ('sin_zero',   c_byte * 8)]
    elif IS_LINUX:
        _fields_ = [
            ('sin_family', c_ushort),
            ('sin_port',   c_uint16),
            ('sin_addr',   c_byte * 4)]

class struct_sockaddr_in6(Structure):
    if IS_DARWIN:
        _fields_ = [
            ('sin6_len',      c_uint8),
            ('sin6_family',   c_uint8),
            ('sin6_port',     c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr',     c_byte * 16),
            ('sin6_scope_id', c_uint32)]
    elif IS_LINUX:
        _fields_ = [
            ('sin6_family',   c_ushort),
            ('sin6_port',     c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr',     c_byte * 16),
            ('sin6_scope_id', c_uint32)]

#            ('ss_pad',    c_uint8 * 126),]
class struct_sockaddr_storage(Structure):
    if IS_DARWIN:
        _fields_ = [
            ('ss_len',    c_uint8),
            ('ss_family', c_uint8),
            ('ss_pad1',   c_uint8 * 6),
            ('ss_align',  c_int64),
            ('ss_pad2',   c_uint8 * 112),]
    elif IS_LINUX:
        _fields_ = [
            ('ss_family', c_uint16),
            ('ss_pad1',   c_char * 6),
            ('ss_align',  c_int64),
            ('ss_pad2',   c_char * 112),]
            
####################################

class Address:
    """ A base class from which all types of addresses are derived """

    def __init__(self, address, family):

        self.in_addr    = address
        self.family     = family
        self.next       = None

        self.printable   = ""

    def __str__(self):

        return self.printable

class IPv4Address(Address):
    """ A class for IP version 4 addresses """

    def __init__(self, address, host=""):

        if not host:
            host = inet_ntop(AF_INET, address)

        super().__init__(address, AF_INET)

        self.original  = host
        self.printable = host

        # IPv4 mapped IPv6 address returned in a dual socket
        self.ipv4mapped = '::ffff:' + ("%08x" % int.from_bytes(self.in_addr,
                                                               'big'))

        # to be set later
        self.service  = 0
        self.sockaddr = None
        self.cname    = ""

    def is_multicast(self):
        """ check whether an address is multicast or not """

        return self.in_addr and (self.in_addr[0] & 0xf0) == 0xe0

class IPv6Address(Address):
    """ A class for IP version 6 addresses """

    def __init__(self, address, host="", scope_id=0):

        if not host:
            host = inet_ntop(AF_INET6, address)

        # the task of whether the '%zone' must be appended to the
        # numeric address or not is fully delegated to Python
        fullhost, _ = getnameinfo((host, 0, 0, scope_id),
                                   NI_NUMERICHOST|NI_NUMERICSERV)

        super().__init__(address, AF_INET6)

        self.scope     = self.get_scope()
        self.original  = host
        self.printable = fullhost
        self.scope_id  = scope_id

        # zone_id may not be checked and carry a wrong interface name
        _, _, zone = fullhost.partition('%')
        self.zone_id = zone

        # IPv6 mapped IPv4 address returned in a dual socket
        self.map4 = None
        if self.in_addr[10:12] == b'\xff\xff':
            self.map4 = inet_ntop(AF_INET, self.in_addr[12:])

        # to be set later
        self.service  = 0
        self.sockaddr = None
        self.cname    = ""

    def get_scope(self):
        """ obtain the embedded scope of an address """

        if int.from_bytes(self.in_addr) == 1:
            scope = SCP_INTLOCAL                  # interface local (loopback)
        elif self.in_addr[0] == 0xfe and ((self.in_addr[1] & 0xc0) == 0x80):
            scope = SCP_LINKLOCAL                 # link local
        elif self.in_addr[0] == 0xfe and ((self.in_addr[1] & 0xc0) == 0xc0):
            scope = SCP_SITELOCAL                 # site local (deprecated)
        elif self.in_addr[0] == 0xfd:
            scope = SCP_GLOBAL               # unique local addresses -> global
        elif self.in_addr[0] == 0xff:
            scope = self.in_addr[1] & 0x0f        # multicast addresses
        else:
            scope = SCP_GLOBAL                    # global unicast addresses

        return scope

    def is_global(self):
        """ check whether address has global scope (includes loopback) """

        return self.scope in (SCP_INTLOCAL, SCP_GLOBAL)

    def is_multicast(self):
        """ check whether an address is multicast or not """

        # Embedded IPv4 address is multicast?
        if self.in_addr and self.map4:
            return (self.in_addr[12] & 0xf0) == 0xe0

        return self.in_addr and self.in_addr[0] == 0xff

class LinkLayerAddress(Address):
    """ A class for layer 2 addresses """

    def __init__(self, address, host=""):

        if not host:
            host = (":").join(["%02x" % x for x in address])

        super().__init__(address, AF_LOCAL_L2)

        self.original  = host
        self.printable = host

##############################

# the following functions check the passed addresses and act as
# factories that perform the actual object instantiation
#
def check_mac_address(taddr: str) -> bytes:
    """ MAC address check """

    mac = taddr.strip().lower()
    for c in mac[:]:
        if c not in HEXDIGITS:
            mac = mac.replace(c, "") 
    try:
        baddr = int(mac, 16).to_bytes(6, 'big')
    except (ValueError, OverflowError) as excp:
        logger.error("Invalid MAC address '%s': %s", taddr, str(excp))
        baddr = None

    return baddr

def check_ip_address(taddr:   str,
                     service: int|str,
                     family:  int,
                     type:    int,
                     proto:   int) -> list:
    """ IP address check """

    flags = AI_PASSIVE|AI_CANONNAME|AI_V4MAPPED
    if family == AF_UNSPEC:
        flags = AI_PASSIVE|AI_NUMERICHOST

    addrlist = []

    try:
        addrlist = getaddrinfo(taddr, service,
                               family=family, type=type, flags=flags)
    except (ValueError, TypeError) as excp:
        logger.error("Invalid type: '%s'", str(excp))
    except gaierror:
        logger.error("Invalid IP address '%s'", taddr)

    return addrlist

def get_linklayer_address(taddr: str) -> LinkLayerAddress:
    """ instantiate a link layer address object """

    baddr = check_mac_address(taddr)

    host = (":").join(["%02x" % x for x in baddr])

    return LinkLayerAddress(baddr, host)

def get_ip_address(taddr:   str,
                   service: int,
                   fam:     int,
                   type:    int,
                   proto:   int) -> IPv4Address|IPv6Address:
    """ get the IP address object from a textual address
        it can be a list of addresses, if resolved from a name
        In such a case, a linked list of addresses is created  """

    addrlist = check_ip_address(taddr, service, fam, type, proto)

    firstaddr = None
    prevaddr  = None
    for addr in addrlist:
        family, _, _, cname, sockaddr = addr
        host  = sockaddr[0]
        baddr = inet_pton(family, host)
        
        if family == AF_INET:
            ipaddr = IPv4Address(baddr, host)
        elif family == AF_INET6:
            scope_id = sockaddr[3]
            ipaddr = IPv6Address(baddr, host, scope_id)

        ipaddr.service  = sockaddr[1]
        ipaddr.sockaddr = sockaddr
        ipaddr.cname    = cname

        if prevaddr:
            prevaddr.next = ipaddr
        else:
            firstaddr = ipaddr
        prevaddr = ipaddr

    return firstaddr
    
def get_address(
          taddr:   str=None,
          service: int|str=0,
          family:  int=AF_UNSPEC,
          type:    int=SOCK_DGRAM,
          proto:   int=0) -> LinkLayerAddress|IPv4Address|IPv6Address:
    """ main entry point to the address factory """

    address = None

    if family == AF_LOCAL_L2:
        address = get_linklayer_address(taddr)
    elif family == AF_UNSPEC:
        if not taddr:
            logger.error("Ambiguous INADDR_ANY address without family. "
              "Specify family or use T_INADDR_ANY for IPv4, '::' for IPv6")
        else:
            address = get_ip_address(taddr, service, AF_UNSPEC, type, proto) 
    elif family == AF_INET:
        if not taddr:
            taddr = "0.0.0.0"
        address = get_ip_address(taddr, service, AF_INET, type, proto)
    elif family == AF_INET6:
        if not taddr:
            taddr = "::"
        address = get_ip_address(taddr, service, AF_INET6, type, proto)
    else:
        logger.error("Invalid address family: '%d'", family)

    return address 

