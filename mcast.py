""" A multicast interface to the socket library 

    Ignacio Martinez (igmartin@movistar.es)
    January 2023

"""

# system imports
import sys
PLATFORM = sys.platform

from socket import (socket, getnameinfo, getservbyname, gaierror,
              AF_UNSPEC, AF_INET, AF_INET6,
              SOCK_DGRAM, IPPROTO_IP, IPPROTO_IPV6,
              NI_NUMERICHOST, NI_NUMERICSERV,
              IP_ADD_MEMBERSHIP, IP_MAX_MEMBERSHIPS, IP_DROP_MEMBERSHIP,
              IPV6_JOIN_GROUP, IPV6_LEAVE_GROUP,
              IP_MULTICAST_LOOP, IP_MULTICAST_TTL, IP_MULTICAST_IF, IP_TOS,
              IPV6_MULTICAST_LOOP, IPV6_MULTICAST_HOPS,
              IPV6_MULTICAST_IF, IPV6_TCLASS,
              SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT,)
if PLATFORM == 'darwin':
    from socket import IP_ADD_SOURCE_MEMBERSHIP, IP_DROP_SOURCE_MEMBERSHIP
from select import select
from ctypes import (Structure, pointer, POINTER, cast, sizeof,
              create_string_buffer,
              c_byte, c_ushort, c_int, c_uint, c_uint8, c_uint16, c_uint32)

# local imports
from util.custlogging import get_logger, ERROR, WARNING, INFO, DEBUG
from util.address import (SCP_INTLOCAL, SCP_LINKLOCAL, SCP_REALMLOCAL, 
              SCP_ADMINLOCAL, SCP_SITELOCAL, SCP_ORGANIZATION, SCP_GLOBAL,
              struct_in_addr, struct_in6_addr,
              struct_sockaddr, struct_sockaddr_storage,
              struct_sockaddr_in, struct_sockaddr_in6,
              IPv4Address, IPv6Address, LinkLayerAddress,
              get_address,)
from util.getifaddrs import (get_interface, get_interface_address,
              get_interface_by_id, get_interface_index,
              find_interface_address,)

#################
# Constants
#

# IP operation mode
#
IPM_IP   = 4
IPM_IPV4 = 4
IPM_IPV6 = 6
IPM_BOTH = 46

# socket state
#
ST_CLOSED    = 0
ST_OPEN      = 1

FLG_BOUND     = 2
FLG_CONNECTED = 4

# check address type
#
CHK_NONE      = 0
CHK_UNICAST   = 1
CHK_MULTICAST = 2

# Buffer size for read operations on sockets
#
BUFFSIZE = 8192

# log object for this module
#
logger = get_logger(__name__, INFO)
#
#     Platform dependencies
#     from netinet/in.h
#
if PLATFORM == 'darwin':
    SIN_LEN                   = True
    IPV6_V6ONLY               = 27
    MCAST_JOIN_GROUP          = 80
    MCAST_LEAVE_GROUP         = 81
    MCAST_JOIN_SOURCE_GROUP   = 82
    MCAST_LEAVE_SOURCE_GROUP  = 83
elif PLATFORM.startswith('linux'):
    SIN_LEN                   = False
    IPV6_V6ONLY               = 26
    IP_ADD_SOURCE_MEMBERSHIP  = 39
    IP_DROP_SOURCE_MEMBERSHIP = 40
    MCAST_JOIN_GROUP          = 42 
    MCAST_LEAVE_GROUP         = 45 
    MCAST_JOIN_SOURCE_GROUP   = 46 
    MCAST_LEAVE_SOURCE_GROUP  = 47 
else:
    logger.error("Non supported or non tested OS: %s. Exiting", PLATFORM)
    sys.exit(1)

###################################################
#
#            C data structures
#
# from netinet/in.h
#
# Structures to set socket options
#
# The following structures have different alignment requierements in MacOS
# and Linux
#
if PLATFORM == 'darwin':
    align = 4
elif PLATFORM.startswith('linux'):
    align = 8

# IP_MULTICAST_IF
class struct_ip_mreqn(Structure):
    _fields_ = [
        ('imr_multiaddr',    struct_in_addr),
        ('imr_address',      struct_in_addr),
        ('imr_ifindex',      c_int),]

# IP_ADD_MEMBERSHIP/IP_DROP_MEMBERSHIP
class struct_ip_mreq(Structure):
    _fields_ = [
        ('imr_multiaddr',    struct_in_addr),
        ('imr_interface',    struct_in_addr),]

# IP_ADD_SOURCE_MEMBERSHIP/IP_DROP_SOURCE_MEMBERSHIP
class struct_ip_mreq_source(Structure):
    _pack_   = align
    _fields_ = [ 
        ('imr_multiaddr',    struct_in_addr),
        ('imr_sourceaddr',   struct_in_addr),
        ('imr_interface',    struct_in_addr),]
   
# MCAST_JOIN_GROUP/MCAST_LEAVE_GROUP
class struct_group_req(Structure):
    _pack_   = align
    _fields_ = [
        ('gr_interface',     c_uint32),
        ('gr_group',         struct_sockaddr_storage),]

# MCAST_JOIN_SOURCE_GROUP/MCAST_LEAVE_SOURCE_GROUP
class struct_group_source_req(Structure):
    _pack_   = align
    _fields_ = [
        ('gsr_interface',    c_uint32),
        ('gsr_group',        struct_sockaddr_storage),
        ('gsr_source',       struct_sockaddr_storage),]

# netinet6/in6.h
#
# IPV6_JOIN_GROUP/IPV6_LEAVE_GROUP
class struct_ipv6_mreq(Structure):
    _fields_ = [
        ('ipv6mr_multiaddr', struct_in6_addr),
        ('ipv6mr_interface', c_uint32),]

#############################################################
#
class McastSocket(socket):
    """ a subclass of 'socket' that simplifies applications doing multicast
        and generic datagram exchange"""

    def __init__(self, ipmode=IPM_BOTH, mcastonly=False, fileno=None):

        if ipmode == IPM_IP:
            family = AF_INET
        elif ipmode in (IPM_IPV6, IPM_BOTH):
            family = AF_INET6
        else:
            logger.error("Invalid socket mode option: %d", ipmode)
            self.state = ST_CLOSED
            raise ValueError("Invalid socket mode option")

        # this is the actual socket creation
        #
        super().__init__(family, SOCK_DGRAM, 0, fileno)

        self.v6only = True
        if ipmode == IPM_BOTH:
            self.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            self.v6only = False

        self.sent     = 0
        self.received = 0

        self.joined        = 0
        self.joined_groups = []

        self.mcastonly = mcastonly

        self.state = ST_OPEN
        self.flags = 0

    def _get_multicast_sockaddr(self, mgroup, service):
        """ obtain the sockaddr structure parameter for a multicast group
            sockaddr in Python's address tuple format (host, port) or
            (host, port, flowinfo, scope_id) for the AF_INET6 family
            used in connect() and sendto() """

        try:
            maddr = get_address(mgroup, service, self.family, SOCK_DGRAM)
        except (ValueError, TypeError) as excp:
            logger.error("getaddrinfo error: '%s', mgroup: %s, service: %s",
                          str(excp), mgroup, service)
            return None
        except gaierror:
            logger.error(
                 "getaddrinfo error: no results for mgroup: %s, service: %s",
                  mgroup, service)
            return None

        if not maddr:
            return None

        if self.mcastonly and not maddr.is_multicast():
            # disallow unicast datagram transmission
            logger.error("invalid multicast group: %s", mgroup)
            return None
        
        if maddr.family == AF_INET6 and self.family == AF_INET:
            logger.error("Cannot transport IPv6 datagrams on IPv4 socket")
            return None
        elif maddr.family == AF_INET and self.family == AF_INET6:
            if self.v6only:
                logger.error("Socket configured solely for IPv6 operation")
                return None

        return maddr.sockaddr

    def _get_interface_sockaddr(self, address, service, family):
        """ obtain the sockaddr structure parameter for an address
            used in bind() """

        if not address:
            if family == AF_INET:
                paddr = "0.0.0.0"
            elif family == AF_INET6:
                paddr = "::"
        else:
            ifc = get_interface_by_id(address)
            if ifc:
                addr  = get_interface_address(ifc.name, family)
                paddr = addr.printable
            else:
                # Must be a valid interface address or group address
                # will complain later otherwise
                paddr = address

        addrobj = get_address(paddr, service, family, SOCK_DGRAM)
        if not addrobj:
            logger.error("Interface sockaddr error. address: %s, service: %s",
                          address, service)
            return None

        return addrobj.sockaddr

    def _build_mreq6(self, gaddr, ifindex):
        """ build an ipv6_mreq structure for IPV6_JOIN_GROUP """

        if not gaddr:
            return None

        mreq6 = struct_ipv6_mreq()
        mreq6.ipv6mr_multiaddr.s6_addr[:] = gaddr.in_addr
        mreq6.ipv6mr_interface = ifindex

        return mreq6

    def _build_mreq(self, gaddr, ifindex):
        """ build an ip_mreq structure for IP_ADD_MEMBERSHIP """

        if not gaddr:
            return None

        iface = get_address("0.0.0.0")
        if ifindex:
            ifc = get_interface_by_id(ifindex) 
            if ifc:
                iface = get_interface_address(ifc.name, AF_INET)
        
        mreq = struct_ip_mreq()
        mreq.imr_multiaddr.s_addr = int.from_bytes(gaddr.in_addr, sys.byteorder)
        mreq.imr_interface.s_addr = int.from_bytes(iface.in_addr, sys.byteorder)

        return mreq

    def _build_mreq_source(self, gaddr, saddr, ifindex):
        """ build an ip_mreq_source structure for IP_ADD_SOURCE_MEMBERSHIP """

        if not gaddr or not saddr:
            return None

        iface = get_address("0.0.0.0")
        if ifindex:
            ifc = get_interface_by_id(ifindex) 
            if ifc:
                iface = get_interface_address(ifc.name, AF_INET)
        
        mreqs = struct_ip_mreq_source()
        mreqs.imr_multiaddr.s_addr  = int.from_bytes(gaddr.in_addr,
                                                     sys.byteorder)
        mreqs.imr_sourceaddr.s_addr = int.from_bytes(saddr.in_addr,
                                                     sys.byteorder)
        mreqs.imr_interface.s_addr  = int.from_bytes(iface.in_addr,
                                                     sys.byteorder)

        return mreqs

    def _build_sockaddr(self, addrobj):
        """ build a sockaddr_storage structure and cast it to
            the appropiate sockaddr according to address family
            for MCAST_JOIN_GROUP and MCAST_JOIN_SOURCE_GROUP
            used in join() and leave() """

        if not addrobj:
            return None

        ss = struct_sockaddr_storage()

        if addrobj.family == AF_INET:
            if SIN_LEN:
                ss.ss_len = sizeof(struct_sockaddr_in)
            ss.ss_family = AF_INET
            sin = cast(pointer(ss), POINTER(struct_sockaddr_in)).contents
            sin.sin_port    = 0
            sin.sin_addr[:] = addrobj.in_addr
        
        elif addrobj.family == AF_INET6:
            if SIN_LEN:
                ss.ss_len = sizeof(struct_sockaddr_in6)
            ss.ss_family = AF_INET6
            sin6 = cast(pointer(ss), POINTER(struct_sockaddr_in6)).contents
            sin6.sin6_port     = 0
            sin6.sin6_flowinfo = 0
            sin6.sin6_addr[:]  = addrobj.in_addr
            sin6.sin6_scope_id = addrobj.scope_id

        return ss

    def _get_optvalue(self, option, gaddr, saddr, ifindex):
        """ build an structure group_req or group_source_req
            if source address is present """

        # This is a mess because IP_ADD_MEMBERSHIP and IPV6_JOIN_GROUP
        # have the same value
        if self.family == AF_INET and (
                option == IP_ADD_MEMBERSHIP or option == IP_DROP_MEMBERSHIP):
            # interface less join/leave
            grp = self._build_mreq(gaddr, ifindex)
        elif self.family == AF_INET and (
                option == IP_ADD_SOURCE_MEMBERSHIP or
                option == IP_DROP_SOURCE_MEMBERSHIP):
            grp = self._build_mreq_source(gaddr, saddr, ifindex)
        elif self.family == AF_INET6 and (
                  option == IPV6_JOIN_GROUP or option == IPV6_LEAVE_GROUP):
            # IPV4 group join on IPV6 socket
            # Note: no IPV6_JOIN_SOURCE_GROUP in BSD. So sources not allowed
            grp = self._build_mreq6(gaddr, ifindex)
        elif option == MCAST_JOIN_GROUP or option == MCAST_LEAVE_GROUP:
            groupaddr = self._build_sockaddr(gaddr)
            grp = struct_group_req()
            grp.gr_interface = ifindex
            grp.gr_group     = groupaddr
        elif option == MCAST_JOIN_SOURCE_GROUP or (
             option == MCAST_LEAVE_SOURCE_GROUP):
            groupaddr  = self._build_sockaddr(gaddr)
            sourceaddr = self._build_sockaddr(saddr)
            grp = struct_group_source_req()
            grp.gsr_interface = ifindex
            grp.gsr_group     = groupaddr
            grp.gsr_source    = sourceaddr
        else:
            logger.error("Invalid socket option for join/leave: %d", option)
            return None

        return bytes(grp)

    def _join_leave(self, mgroup, ifaddr, source, isjoin=True):

        tag = "join" if isjoin else "leave"

        if self.state == ST_CLOSED:
            logger.error("cannot %s group. Socket is closed", tag)
            return 1

        if isjoin and self.joined >= IP_MAX_MEMBERSHIPS:
            logger.error("exceeded max number of multicast groups %s", tag)
            return 1

        ifindex = 0
        if ifaddr:
            ifindex = get_interface_index(ifaddr)
            
        # ifaddr = None, "" or 0 are an indication to the kernel
        # to select a joining interface using routing information
        # this seemingly works on Linux unlike on MacOS
        if ifaddr and (ifindex == 0):
            logger.error("Invalid interface name or address: %s", ifaddr)
            return 1

        gaddr = get_address(mgroup, type=SOCK_DGRAM)
        if not gaddr or not gaddr.is_multicast():
            logger.error("Invalid multicast address format: %s", mgroup)
            return 1
        if gaddr.family == AF_INET6 and ifindex == 0:
            ifindex = gaddr.scope_id
            if ifindex == 0:
                logger.error(
                   "Must specify join interface for IPv6 address: %s", gaddr)
                return 1

        saddr = None
        if source:
            saddr = get_address(source)
            if not saddr or saddr.is_multicast():
                logger.error("Invalid unicast source address: %s", source)
                return 1
            if saddr.family != gaddr.family:
                logger.warning("Group/Source address family mismatch")

        if PLATFORM == 'darwin':
            # MacOS requires 'proto' to be aligned with the socket family
            if self.family == AF_INET:
                proto = IPPROTO_IP
            elif self.family == AF_INET6:
                proto = IPPROTO_IPV6
        else:
            # Linux ipv6 sockets allow for joins on either family addresses
            if gaddr.family == AF_INET:
                proto = IPPROTO_IP
            elif gaddr.family == AF_INET6:
                proto = IPPROTO_IPV6

        # Default socket option for any-source groups in all platforms
        join_option  = MCAST_JOIN_GROUP
        leave_option = MCAST_LEAVE_GROUP
        if source:
            # Default socket option for source-specific groups in all platforms
            join_option  = MCAST_JOIN_SOURCE_GROUP    
            leave_option = MCAST_LEAVE_SOURCE_GROUP    
        if PLATFORM == 'darwin':
            # Join v6 group on v4 socket. Not possible on MacOS
            if self.family == AF_INET and gaddr.family == AF_INET6:
                logger.error(
                 "Address incompatible with IPV4 socket family: %s", gaddr)
                return 1
            if self.family == AF_INET and not ifindex:
                # No interface. Let the system find one
                join_option  = IP_ADD_MEMBERSHIP
                leave_option = IP_DROP_MEMBERSHIP
                if source:
                    join_option  = IP_ADD_SOURCE_MEMBERSHIP
                    leave_option = IP_DROP_SOURCE_MEMBERSHIP
            if self.family == AF_INET6 and gaddr.family == AF_INET:
                # v4 join on v6 socket. Available on MacOS 
                if not source:
                    gaddr = get_address(gaddr.ipv4mapped)
                    join_option  = IPV6_JOIN_GROUP
                    leave_option = IPV6_LEAVE_GROUP
            if self.family == AF_INET6 and gaddr.family == AF_INET6:
                if gaddr.is_v4mapped() and not source:
                    # v6 mapped v4 multicast address
                    join_option  = IPV6_JOIN_GROUP
                    leave_option = IPV6_LEAVE_GROUP

        if isjoin:
            option = join_option
        else:
            option = leave_option

        value = self._get_optvalue(option, gaddr, saddr, ifindex)
        if not value:
            return 1

        try:
            # this is the actual IGMP join/leave
            #
            logger.debug("proto: %d, option: %d, value: %s, len: %d",
                          proto, option, value, len(value))
            self.setsockopt(proto, option, value)
        except OSError as ose:
            logger.error("Multicast %s group error (%d): %s",
                          tag, ose.errno, ose.strerror)
            return 1

        return 0

#############
# public
#
    def bind(self, address, service, reuseport=0):
        """ local interface to bind()
            if address is an interface address, permit unicast UDP traffic
            if address is a multicast group, filter datagrams on that group
            if address is INADDR_ANY, permit any traffic
        """

        if self.state == ST_CLOSED:
            logger.error("cannot bind socket to address. Socket is closed")
            return 1

        sockaddr = self._get_interface_sockaddr(address, service, self.family)

        if not sockaddr:
            logger.error("Invalid interface for bind(): %s", address)
            return 1

        # if binding to a non zero port set to reuse address and, optionally,
        # to reuse port so other sockets can bind to the same address and port
        #
        if sockaddr[1] > 0:
            reuseaddress = 1
            self.set_recvoptions(reuseaddress, reuseport)

        try:
            super().bind(sockaddr)
        except OSError as ose:
            logger.error("Error binding mcast service to socket: %s",
                          ose.strerror)
            return 1

        self.flags |= FLG_BOUND

        return 0

    def connect(self, mgroup, service):
        """ connect this socket to a remote socket with address 'mgroup'
            and port 'service'. Datagrams can be sent with 'send()'
            without specifying group and service """    

        if self.state == ST_CLOSED:
            logger.error("cannot connect socket to remote address. "
                         "Socket is closed")
            return 1
    
        address = self._get_multicast_sockaddr(mgroup, service)

        if not address:
            logger.error("Invalid multicast address (connect): %s", mgroup)
            return 1

        try:
            super().connect(address) 
        except OSError as ose:
            logger.error("cannot connect to remote address (%d), %s",
                          ose.errno, ose.strerror)
            return 1

        self.flags |= FLG_CONNECTED

        return 0

    def recvfrom(self, encoding=None):
        """ receive datagrams from socket """

        if self.state == ST_CLOSED:
            logger.error("cannot receive datagrams on socket. Socket is closed")
            return None, "", 0

        buff, address = super().recvfrom(BUFFSIZE)

        host, service = getnameinfo(address, NI_NUMERICHOST|NI_NUMERICSERV)

        if len(address) == 4:            # family is AF_INET6
            addrobj = get_address(host)
            if addrobj.map4:             # is a mapped IPv4 address
                host = addrobj.map4      # return plain IPv4 address instead

        if encoding:
            try:
                buff = buff.decode(encoding=encoding)
            except ValueError:
                logger.error("Invalid codec '%s' for decoding bytes buffer",
                              encoding)

        return buff, host, service

    def sendto(self, buffer, mgroup, service, encoding='utf-8'):
        """ send datagram to a remote mgroup/service combination """

        if self.state == ST_CLOSED:
            logger.error("cannot send datagrams on socket. Socket is closed")
            return 0
    
        address = self._get_multicast_sockaddr(mgroup, service)

        if not address:
            logger.error("Invalid multicast group address/service: %s, %s",
                          mgroup, service)
            return 0

        if isinstance(buffer, str):
            try:
                buffer = buffer.encode(encoding=encoding)
            except ValueError:
                logger.error("Invalid encoding '%s' for string '%s'",
                              encoding, buffer)
                return 0

        try:
            sent = super().sendto(buffer, address)
        except OSError as ose:
            logger.error("error sending datagram to dest %s: %s",
                          address, ose.strerror)
            sent = 0

        return sent

    def close(self):

        super().close()

        self.state = ST_CLOSED

    def join(self, mgroup, ifaddr=None, source=None):
        """ join multicast group 'mgroup' at interface address 'ifaddr'
            with optional SSM source 'source' """

        if self._join_leave(mgroup, ifaddr, source, isjoin=True) != 0:
            return 1

        self.joined += 1
        self.joined_groups.append((mgroup, ifaddr, source))

        return 0

    def leave(self, mgroup, ifaddr=None, source=None):
        """ Leave multicast group 'mgroup' at interface 'ifaddr'
            with optional SSM source 'source' """

        if self._join_leave(mgroup, ifaddr, source, isjoin=False) != 0:
            return 1

        self.joined -= 1
        self.joined_groups.remove((mgroup, ifaddr, source))

        return 0

    def leaveall(self):

        res = 0
        for mgroup, ifaddr, source in self.joined_groups:
            if self._join_leave(mgroup, ifaddr, source, isjoin=False) != 0:
                res = 1

        return res

    def set_recvoptions(self, reuseaddress=-1, reuseport=-1):
        """ set the socket receiving options """

        if self.state == ST_CLOSED:
            logger.error("cannot set options on socket. Socket is closed")
            return 1

        try:
            if (reuseaddress in (0,1) and
                reuseaddress != self.getsockopt(SOL_SOCKET, SO_REUSEADDR)):
                self.setsockopt(SOL_SOCKET, SO_REUSEADDR, reuseaddress)
            if (reuseport in (0, 1) and
                reuseport != self.getsockopt(SOL_SOCKET, SO_REUSEPORT)):
                self.setsockopt(SOL_SOCKET, SO_REUSEPORT, reuseport)
        except OSError as ose:
            logger.error("Error trying to set socket receiving options: %s",
                          ose.strerror)
            return 1

        return 0

    def setfwdint(self, fwdint:int):
        """ set fordwarding interface for multicast packets
            MacOS accepts in_addr, ip_mreq, ip_mreqn for IPv4; int for IPv6
            Linux only accepts in_addr for IPV4; int for IPv6
            MacOS blocks setting back to default forwarding intf for IPV6 """

        # we use a single input type here: int representing interface index
        #
        if self.family == AF_INET:
            if not fwdint:
                # fwdint = None, 0
                fwif = bytes(sizeof(struct_in_addr))
            else:
                iface = get_interface_by_id(fwdint)
                if not iface:
                    logger.error("Invalid forwarding interface '%s'", fwdint)
                    return
                addr = get_interface_address(iface.name, AF_INET)
                if not addr:
                    logger.error(
                       "Invalid address at forwarding interface '%s'",
                        iface.name)
                    return
                fwif = addr.in_addr
            self.setsockopt(IPPROTO_IP, IP_MULTICAST_IF, fwif)

        elif self.family == AF_INET6:
            self.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_IF, fwdint)

    def getfwdint(self):

        if self.family == AF_INET:
            bytesval = self.getsockopt(IPPROTO_IP, IP_MULTICAST_IF, 4)
            addr = find_interface_address(bytesval, AF_INET)
            if not addr:
                return 0

            return addr.interface.index

        elif self.family == AF_INET6:

            return self.getsockopt(IPPROTO_IPV6, IPV6_MULTICAST_IF)

    def set_sendoptions(self, fwdif=None, loop=-1, ttl=-1, prec=-1):
        """ set various options for sending multicast datagrams
            options include output interface, ttl, loopback reception
            and IP precedence """

        if self.state == ST_CLOSED:
            logger.error("cannot set options on socket. Socket is closed")
            return 1

        if self.family == AF_INET:
            proto    = IPPROTO_IP
            opt_loop = IP_MULTICAST_LOOP
            opt_ttl  = IP_MULTICAST_TTL
            opt_mif  = IP_MULTICAST_IF
            opt_tos  = IP_TOS
        elif self.family == AF_INET6:
            proto    = IPPROTO_IPV6
            opt_loop = IPV6_MULTICAST_LOOP
            opt_ttl  = IPV6_MULTICAST_HOPS
            opt_mif  = IPV6_MULTICAST_IF
            opt_tos  = IPV6_TCLASS

        fwdint = -1
        if fwdif == 0:
            fwdint = 0
        elif fwdif:
            fwdint = get_interface_index(fwdif)

        try:
            if loop in (0, 1) and loop != self.getsockopt(proto, opt_loop):
                self.setsockopt(proto, opt_loop, loop)
            if 0 < ttl < 256 and ttl != self.getsockopt(proto, opt_ttl):
                self.setsockopt(proto, opt_ttl,  ttl)
            if fwdint >= 0 and fwdint != self.getfwdint():
                self.setfwdint(fwdint)
            if prec > 0 and prec != self.getsockopt(proto, opt_tos):
                self.setsockopt(proto, opt_tos,  (prec & 0x07) << 5)
        except OSError as ose:
            logger.error("Error trying to set mcast send socket options: %s",
                          ose.strerror)
            return 1

        return 0

# High level interface
#

class SenderMcastSocket(McastSocket):

    def __init__(self, mgroup, port, interface=None):

        self.mgroup    = mgroup
        self.port      = port

        maddr = get_address(mgroup, port)
        if not maddr:
            logger.error("Invalid multicast group/port pair '%s, %d'",
                          mgroup, port)
            raise ValueError

        if not maddr.is_multicast():
            logger.error("Invalid multicast group '%s'", mgroup)
            raise ValueError

        mode = IPM_IPV4
        if maddr.family == AF_INET6:
            mode = IPM_IPV6

        super().__init__(mode)

        if interface:
            self.set_sendoptions(fwdif=interface)

    def msend(self, buffer, encoding='utf-8'):

        return self.sendto(buffer, self.mgroup, self.port, encoding)

class ReceiverMcastSocket(McastSocket):

    def __init__(self, mgroup, port, interface=None):

        maddr = get_address(mgroup, port)
        if not maddr:
            logger.error("Invalid multicast group/port pair '%s, %d'",
                          mgroup, port)
            raise ValueError

        if not maddr.is_multicast():
            logger.error("Invalid multicast group '%s'", mgroup)
            raise ValueError

        mode = IPM_IPV4
        if maddr.family == AF_INET6:
            mode = IPM_IPV6

        super().__init__(mode)

        res = self.bind(mgroup, port)
        if res == 0:
            res = self.join(mgroup, interface)

        if res != 0:
            raise ValueError

    def mreceive(self, encoding=None):

        buffer, address, port = self.recvfrom(encoding)

        return buffer, address

##########
# utility functions
#

socketlist = []

def mcast_read(stop=False):

    while True:
        if stop:
            return
        try:
            ready, _, _ = select(socketlist, [], [])
        except KeyboardInterrupt:
            break
        for sock in ready:
            yield sock.recvfrom()
    
def mcast_server_stop():
    """ leave multicast groups and close sockets """

    mcast_read(stop=True)

    for sock in socketlist:
        sock.leaveall()
        sock.close()

    return 0

def do_something():

    for buff, addr, port in mcast_read():

        if not buff:
            print("terminated")
            break

        print("msg:", buff, "addr:", addr, "port:", port)

    return 0

def mcast_server(grouplist, port, interface, task=do_something):
    """ initialize multicast server. Do parameter checking,
        create sockets and join groups
        arguments
        grouplist: tuple (group [, join-interface [, source]])
        port: the server port
        interface: the default interface for joins (can be overriden in tuple)
    """

    v4groups   = []
    v6groups   = []

    # check port
    #
    service = None
    if isinstance(port, int):
        service = port
    elif isinstance(port, str):
        try:
            service = getservbyname(port)
        except (TypeError, OSError) as excp:
            logger.error("getservbyname: %s", str(excp))

    if not service:
        logger.error("error: Invalid port: %s", port)
        return 1
    
    # check default joining interface (socket bound to all interfaces)
    # if null, it must be explicitly set in grouplist
    #
    ifindex = 0
    if interface:
        ifindex = get_interface_index(interface)

    # build per-family lists of multicast groups
    #
    for tupl in grouplist:
        if not isinstance(tupl, tuple or list):
            logger.error("Invalid type for parameter 'grouplist'. "
                         "Must be 'tuple' or 'list'")
            return 1

        ifaddr = ifindex
        source = None

        if len(tupl) > 2:
            source = tupl[2]
        if len(tupl) > 1:
            ifaddr = tupl[1]
        if len(tupl) > 0:
            group = tupl[0]
        else:
            logger.error("Empty entry in group list")
            continue

        maddr = get_address(group, type=SOCK_DGRAM)
        if not maddr:
            logger.error("Invalid multicast group: %s", group)
            return 1

        # MacOS disallows joins for source-specific v4 groups on v6 sockets
        if PLATFORM == 'darwin' and maddr.family == AF_INET and source:
            v4groups.append((group, ifaddr, source))
        else:
            v6groups.append((group, ifaddr, source))

    # check that at least one list is not empty
    #
    want4 = len(v4groups) > 0
    want6 = len(v6groups) > 0
    if not want4 and not want6:
        logger.error("error: No multicast group addresses available")
        return 1

    # socket creation and binding
    #
    if want4 and want6:
        msock = McastSocket(IPM_BOTH)
        socketlist.append(msock)
        if PLATFORM == 'darwin':
            msock4 = McastSocket(IPM_IP)
            socketlist.append(msock4)
            msock.bind("::", service, reuseport=1)
            msock4.bind("0.0.0.0", service, reuseport=1)
        else:
            msock.bind("::", service)
    elif want6:
        msock = McastSocket(IPM_IPV6)
        socketlist.append(msock)
        msock.bind("::", service)
    elif want4:
        msock = McastSocket(IPM_IP)
        socketlist.append(msock)
        msock.bind("0.0.0.0", service)

    # group joining
    #
    if want6 and want4 and PLATFORM == 'darwin':
        # This requires an extra socket for v4 joins
        for group, intf, source in v4groups[:]:
            if msock4.join(group, intf, source) != 0:
                v4groups.remove((group, intf, source))
    else:
        if want6:
            for group, intf, source in v6groups[:]:
                if msock.join(group, intf, source) != 0:
                    v6groups.remove((group, intf, source))
        if want4:
            for group, intf, source in v4groups[:]:
                if msock.join(group, intf, source) != 0:
                    v4groups.remove((group, intf, source))

    task()

    mcast_server_stop()

    return 0

