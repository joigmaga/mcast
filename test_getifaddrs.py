#! /usr/bin/env python3

from sys import platform
from util.getifaddrs import (get_network_interfaces,
                  get_interface, get_interface_names,
                  get_interface_addresses, get_interface_address,
                  find_interface_address,
                  print_interface_addresses, print_interface_address,
                  GIA_AF_UNSPEC, GIA_AF_LINK, GIA_AF_INET, GIA_AF_INET6,
                  GIA_SCP_ALL, GIA_SCP_HOST, GIA_SCP_LINK, GIA_SCP_GLOBAL)

if platform == 'darwin':
    int1 = "lo0"        # loopback
    int2 = "en0"        # ethernet
    int3 = "en2"        # wifi

# get_networkinterfaces()
#
ni = get_network_interfaces()
assert len(ni) > 0

map = ni.mapping
assert len(map) > 0

names = tuple(map.keys())

# get_interface_names()
#
gin = get_interface_names()
assert isinstance(gin, tuple) and len(gin) > 0
assert names == gin

# get_interface()
#
ifcs = get_interface(int1)
ifci = get_interface(ifcs.index)
assert ifcs.name == ifci.name

ifcs = get_interface(int2)
ifci = get_interface(ifcs.index)
assert ifcs.name == ifci.name

ifcs = get_interface(int3)
ifci = get_interface(ifcs.index)
assert ifcs.name == ifci.name

# get_interface_addresses() and get_interface_address()
#
ifaddrs1 = get_interface_addresses(int1)
ifaddrs2 = get_interface_addresses(int2, GIA_AF_INET6, GIA_SCP_LINK)
ifaddrs3 = get_interface_addresses(int3)

ifaddr1 = get_interface_address(int1, GIA_AF_INET)
ifaddr2 = get_interface_address(int2, GIA_AF_INET6)
ifaddr3 = get_interface_address(int3, GIA_AF_LINK)

assert ifaddr1 not in ifaddrs1
assert ifaddr2 not in ifaddrs2
assert ifaddr3 not in ifaddrs3

# print_interface_addresses() and print_interface_address()
#
aa1 = print_interface_addresses(int1)
aa2 = print_interface_addresses(int2)
aa3 = print_interface_addresses(int3)
xa2 = print_interface_addresses(int3, fullfmt=True)
assert xa2 != aa2

a1 = print_interface_address(int2, GIA_AF_INET6, GIA_SCP_LINK, False)
a2 = print_interface_address(int2, GIA_AF_INET6, GIA_SCP_LINK, False, True)
a3 = print_interface_address(int2, GIA_AF_INET6, GIA_SCP_LINK, False, False)
assert a2 != a3

# find_interface_address()
#
addr1 = find_interface_address(a1, GIA_AF_INET6)
addr2 = find_interface_address(a2, GIA_AF_INET6)
addr3 = find_interface_address(a3, GIA_AF_INET6, int2)
assert str(addr1) == str(addr2) == str(addr3)

print("All tests passed successfully")
