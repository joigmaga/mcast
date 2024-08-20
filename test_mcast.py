#! /usr/bin/env python3

from sys import platform, exit
from os import getpid
from time import sleep
from select import select
from argparse import ArgumentParser

from mcast import (McastSocket,
                   IPM_IP, IPM_IPV6, IPM_BOTH,
                   AF_INET, AF_INET6,)
from util.address     import SCP_LINKLOCAL
from util.getifaddrs  import get_interface, get_interface_address
from util.custlogging import get_logger, ERROR, WARNING, INFO

def who_serves():
    """ decide who takes either client role or server
        before running the test """

    ifaddr = mt_ifaddr4
    group  = "235.36.37.38"
    port   = 9000

    me = bytes(mt_ifaddr4 + "|" + mt_ifaddr6 + "&" + str(getpid()), 'ascii')
    sep = b' '
    msg1 = b'Hi there'
    msg2 = b'You serve'
    msg3 = b'I serve'

    msock = McastSocket(IPM_IP)
    msock.bind("0.0.0.0", port, reuseport=1)
    msock.join(group, opts.interface)
    msock.set_sendoptions(fwdif=ifaddr, loop=1, ttl=1)

    iserve  = False
    iclient = False
    started = False

    msg = me + sep + msg1
    tout = 1

    for _ in range(30):
        msock.settimeout(tout)
        try:
            while True:
                buff, _, _ = msock.recvfrom()
                who, what = buff.split(maxsplit=1)
                if who != me:
                    break
        except OSError:
            msock.sendto(msg, group, port)
        else:
            if what == msg1:
                if not started:
                    msg = me + sep + msg2
                    msock.sendto(msg, group, port)
                started = True
            elif what == msg2:
                msg = me + sep + msg3
                msock.sendto(msg, group, port)
                iserve = True
                break
            elif what == msg3:
                iclient = True
                break
        finally:
            tout = 5

    msock.close()

    role = 1 if iserve else 0 if iclient else -1
    if role == -1:
        return role, "", ""

    who = who.decode('ascii')
    who,  _, _    = who.partition('&')
    rem4, _, rem6 = who.partition('|')
    #rem6 += "%" + opts.interface

    return role, rem4, rem6

def run_client():
    """ run test as client """

    msock4  = McastSocket(IPM_IP)
    msock6  = McastSocket(IPM_IPV6)
    msock46 = McastSocket(IPM_BOTH)

    # unicast
    #
    msg = b'Hi you unicast'
    msock4.set_sendoptions(fwdif=mt_ifaddr4,      loop=0, ttl=1)
    msock6.set_sendoptions(fwdif=opts.interface,  loop=0, ttl=1)
    msock46.set_sendoptions(fwdif=opts.interface, loop=0, ttl=1)
    logger.info("sending unicast messages to server ...")

    # slow down a bit the unicast datagram rate so they don't look like a flood attack
    to4 = False
    socklist = [msock4, msock6, msock46]
    while socklist:
        _, ready, _ = select([], socklist, [])

        for msock in ready:
            if msock == msock4:
                msock.sendto(msg, mt_rem4, mt_port4)
                logger.info("ipv4 socket")
                socklist.remove(msock)
            elif msock == msock6:
                msock.sendto(msg, mt_rem6, mt_port6)
                logger.info("ipv6 only socket")
                socklist.remove(msock)
            elif msock == msock46 and not to4:
                sleep(0.5)
                msock.sendto(msg, mt_rem4, mt_port46)
                logger.info("ipv4 to v4/v6 socket")
                to4 = True
            else:
                sleep(0.5)
                msock.sendto(msg, mt_rem6, mt_port46)
                logger.info("ipv6 to v4/v6 socket")
                socklist.remove(msock)

    # response from server to unicast datagrams
    socklist = [msock4, msock6, msock46]
    while True:
        ready, _, _ = select(socklist, [], [], 6)
        if not ready:
            break

        for msock in ready:
            buff, addr, port = msock.recvfrom()
            logger.info("received message from %s (%s): %s", addr, port, buff)

    # multicast 
    #
    msg = b'Hi there multicast'
    if mt_islocal:
        msock4.set_sendoptions(loop=1)
        msock6.set_sendoptions(loop=1)
        msock46.set_sendoptions(loop=1)
    logger.info("sending multicast messages to server ...")
    msock4.sendto(msg,  mt_group4, mt_port4)
    msock6.sendto(msg,  mt_group6, mt_port6)
    msock46.sendto(msg, mt_group4, mt_port46)
    msock46.sendto(msg, mt_group6, mt_port46)

    # response from server to multicast datagrams
    socklist = [msock4, msock6, msock46]
    while True:
        ready, _, _ = select(socklist, [], [], 6)
        if not ready:
            break

        for msock in ready:
            buff, addr, port = msock.recvfrom()
            logger.info("received response from %s (%s): %s", addr, port, buff)

    msock4.close()
    msock6.close()
    msock46.close()

    return 0

def run_server():

    msock4  = McastSocket(IPM_IP)
    msock6  = McastSocket(IPM_IPV6)
    msock46 = McastSocket(IPM_BOTH)
    if PLATFORM == 'darwin':
        msock42 = McastSocket(IPM_IP)

    msock4.bind("0.0.0.0",    mt_port4)
    msock6.bind("::",  mt_port6)
    if PLATFORM == 'darwin':
        msock46.bind("::", mt_port46, reuseport=1)
        msock42.bind("0.0.0.0",   mt_port46, reuseport=1)
    else:
        msock46.bind("::", mt_port46)

    msock4.set_sendoptions(fwdif=mt_ifaddr4, loop=0, ttl=1)
    msock6.set_sendoptions(fwdif=mt_index,   loop=0, ttl=1)
    msock46.set_sendoptions(fwdif=mt_index,  loop=0, ttl=1)
    if PLATFORM == 'darwin':
        msock42.set_sendoptions(fwdif=mt_ifaddr4, loop=0, ttl=1)

    # join and leave groups/channels
    #
    msock4.join(mt_group4,  mt_index)
    msock4.join(mt_group4s, mt_index, mt_source4)
    msock6.join(mt_group6,  mt_index)
    msock6.join(mt_group6s, mt_index, mt_source6)
    if PLATFORM.startswith('linux'):
        msock46.join(mt_group4,  mt_index)
        msock46.join(mt_group4s, mt_index, mt_source4)
    else:
        msock42.join(mt_group4,  mt_index)
        msock42.join(mt_group4s, mt_index, mt_source4)
    msock46.join(mt_group6,  mt_index)
    msock46.join(mt_group6s, mt_index, mt_source6)

    msg = b'Hi dude'
    msocklist = [msock4, msock6, msock46]
    if PLATFORM == 'darwin':
        msocklist.append(msock42)
    while True:
        ready, _, _ = select(msocklist, [], [], 11)

        if not ready:
            break

        for msock in ready:
            # read socket and reply unicast to client
            buff, addr, port = msock.recvfrom()
            _, lport = msock.getsockname()[:2]
            logger.info("received message from %s for service (%s): %s",
                   addr, lport, buff)
            logger.info("replying to client")
            msock.sendto(msg, addr, port)

    msock4.leave(mt_group4,  mt_index)
    msock4.leave(mt_group4s, mt_index, mt_source4)
    msock6.leave(mt_group6,  mt_index)
    msock6.leave(mt_group6s, mt_index, mt_source6)
    if PLATFORM.startswith('linux'):
        msock46.leave(mt_group4,  mt_index)
        msock46.leave(mt_group4s, mt_index, mt_source4)
    else:
        msock42.leave(mt_group4,  mt_index)
        msock42.leave(mt_group4s, mt_index, mt_source4)
    msock46.leave(mt_group6,  mt_index)
    msock46.leave(mt_group6s, mt_index, mt_source6)

    msock4.close()
    msock6.close()
    msock46.close()
    if PLATFORM == 'darwin':
        msock42.close()

    return 0

#####
#
logger = get_logger(__name__, INFO)

PLATFORM = platform

argp = ArgumentParser(description='mcast test suite')
argp.add_argument('-v', '--version', action='version',
            version='mcast test suite version 1.0')
argp.add_argument('interface', action='store',
            help='interface name')
opts = argp.parse_args()

mt_ifc = get_interface(opts.interface)
if not mt_ifc:
    logger.error("invalid interface: %s", opts.interface)
    exit(1) 
mt_index  = mt_ifc.index
mt_local4 = get_interface_address(opts.interface, AF_INET)
mt_local6 = get_interface_address(opts.interface, AF_INET6, SCP_LINKLOCAL)
if not mt_local4 or not mt_local6:
    logger.error("could not find valid addresses for interface: %s", opts.interface)
    exit(1)
mt_ifaddr4 = mt_local4.printaddress()
mt_ifaddr6 = mt_local6.printaddress()

mt_group6  = "ff12::2345"
mt_group6s = "ff12::3456"
mt_group4  = "235.6.7.8"
mt_group4s = "235.6.7.9"

mt_port4   = 4000
mt_port6   = 6000
mt_port46  = 4600

mt_source4 = mt_ifaddr4
mt_source6 = mt_ifaddr6

mt_who, mt_rem4, mt_rem6 = who_serves()
mt_islocal = mt_rem4 == mt_ifaddr4
if mt_who == 1:
    logger.info("running test as server")
    run_server()
elif mt_who == 0:
    logger.info("running test as client")
    run_client()
else:
    logger.error("test not started. timed out")

exit(0)
