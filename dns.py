#!/usr/bin/env python3
import argparse
import os
from scapy.all import *

def get_IP(hostname, dns, record):
    ADDR = ''

    # Set localhost IP address
    if hostname == "localhost":
        if record == "A":
            ADDR = "127.0.0.1"
        elif record == "AAAA":
            ADDR = "::1"
    else:
        answer = sr1(IP(dst=dns)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname,qtype=record)))
        ADDR = answer.an.rdata
    return ADDR

def parser():
    parser = argparse.ArgumentParser(description='Query Google\'s DNS server for the IPv4 address of a hostname')
    parser.add_argument('-H', '--hostname',
                        dest='host',
                        required=True,
                        help='Set hostname')
    parser.add_argument('-d', '--dns',
                        dest='dns',
                        help='Set DNS server')
    parser.add_argument('--ipv4',
                        dest='ipv4',
                        help='Get IPv4 address',
                        action='store_true')
    parser.add_argument('--ipv6',
                        dest='ipv6',
                        help='Get IPv6 address',
                        action='store_true')
    return parser.parse_args()

def main():
    args = parser()
    hostname = args.host
    dns = args.dns

    if dns == None:
        dns = '8.8.8.8'
    if os.geteuid() == 0:
        if args.ipv4:
            print(get_IP(hostname, dns, "A"))
        if args.ipv6:
            print(get_IP(hostname, dns, "AAAA"))
    else:
        exit("Script needs to be run as root user")

if __name__ == "__main__":
    main()
