#! /usr/bin/env python3

from socket import AF_INET, AF_INET6, AF_LINK
from util.address import get_address

a = get_address("130.206.1.5", 0, AF_INET)
b = get_address("FE80::45:67", 'www', AF_INET6)
c = get_address("FE80::45:67%eth9", 80, AF_INET6)

print(a, b, c)

x = get_address("130.206.1.588", 0, AF_INET)
y = get_address("130.206.1.588", 0, 888)
z = get_address("130.206.1.5", 0, 888)

print(x, y, z)

x = get_address("ff::80:1:2", 'xyz', AF_INET6)
y = get_address("ff::80:1:xz", 99, AF_INET6)
z = get_address("ff::80:1:2", -1, 888)

print(x, y, z)
