#!/usr/bin/env python

from scapy.all import *
from netaddr import *
import random
import argparse
import socket


def port(arg):
    """returns an int if the string argument represents a valid port number"""
    tmp = int(arg)
    if tmp < 0 or tmp > 65535:
        raise ValueError('invalid port specified {arg}')
    return tmp


def portlist(arg):
    """returns a list of ports from a string input"""
    port_list = str(arg).split(',')
    port_array = []
    for p in port_list:
        range_list = p.split('-')
        if len(range_list) == 1:
            port_array.append(port(p))
        elif len(range_list) == 2:
            int_list = array.array('H')
            int_list.append(int(range_list[0]))
            int_list.append(int(range_list[1]))
            for pp in range(min(int_list), max(int_list) + 1):
                port_array.append(port(pp))
        else:
            raise ValueError('invalid range specified {p}')
    return port_array


def hostlist(arg):
    """returns a list of hosts from a string input"""
    host_list = str(arg).split(',')
    host_array = []
    for host in host_list:
        host_array.append(socket.gethostbyname(host))
    return host_array


parser = argparse.ArgumentParser(
    prog='nmap',
    description='minimal python version of nmap using scapy')

parser.add_argument(
    'targets', type=hostlist, help='target host(s) to be scanned')

parser.add_argument(
    '-p', type=portlist, default='0-65535',
    help='comma delimited list of ports to scan on the host.'
    'hyphenated ranges also accepted.')

parser.add_argument(
    '--host-timeout', type=int, default=5,
    help='timeout before moving on to a new port/host in seconds')

parser.add_argument(
    '--scan-delay', type=int, default=0,
    help='delay between probes in seconds')

parser.add_argument(
    '-g', type=port, help='source port to use')

parser.add_argument(
    '-S', type=hostlist,
    help='comma separated source ip address(es) to use')

# TODO: implement this
parser.add_argument(
    '--spoof-mac', type=EUI,
    help='source mac address to use')

parser.add_argument(
    '--mtu', type=int, default=1480,
    help='fragment packets using the given mtu')

group = parser.add_mutually_exclusive_group(required=True)

group.add_argument(
    '-sU', help='perform UDP scan', action='store_true')

group.add_argument(
    '-sS', help='perform SYN scan', action='store_true')

args = vars(parser.parse_args())

scan_instances = []
for target in args['targets']:
    for p in args['p']:
        scan_instances.append((target, p))

random.shuffle(scan_instances)

if args['sU']:
    # TODO: randomize udp payload
    protocol = UDP()
elif args['sS']:
    protocol = TCP(
        flags="S",
        options=[('MSS', 1460), ('NOP', ()), ('SAckOK', ''), ('WScale', 10)])
else:
    raise ValueError('unknown scan type specified')

ip = IP()
for scan in scan_instances:
    print 'scanning {} on port {}'.format(scan[0], scan[1])

    protocol.dport = scan[1]

    if args['g'] != None:
        protocol.sport = args['g']
    else:
        protocol.sport = RandShort() % (65535 - 1025) + \
            1025  # limit to reasonable ephemeral source ports

    if hasattr(protocol, 'seq'):
        protocol.seq = RandShort()

    ip.dst = scan[0]
    ip.id = RandShort()

    if args['S'] != None:
        ip.src = args['S'][Rand() % len(args['S'])]

    res, unans = scapy.all.sr(
        fragment(ip / protocol, args['mtu']),
        inter=args['scan_delay'],
        timeout=args['host_timeout'])

    if res:
        res.show()
