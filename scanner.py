#!/usr/bin/env python

from scapy.all import *
import argparse
import socket

parser = argparse.ArgumentParser(
    prog='scanner',
    description='stealthily scans a network')

parser.add_argument(
    'target', default='127.0.0.1', type=socket.gethostbyname,
    help='target host to be scanned')

parser.add_argument(
    '-port', type=int, action='append',
    help='ports to scan on the host')

args = vars(parser.parse_args())

for port in args['port']:
    p = sr1(IP(dst=args['target'])/TCP(dport=port, flags="S"))

    if p:
        p.show()

