#!/usr/bin/env python3
import argparse
from scapy.all import *

def get_IPv4(hostname, dns):
    IPv4 = ''
    
    # Localhost is always 127.0.0.1
    if hostname == 'localhost':
        IPv4 = '127.0.0.1'
    else:
        answer = sr1(IP(dst=dns)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname,qtype="A")))
        IPv4 = str(answer.an.rdata)
    return IPv4

def get_IPv6(hostname, dns):
    IPv6 = ''
    
    # Localhost is always ::1
    if hostname == 'localhost':
        IPv6 = '::1'
    else:
        answer = sr1(IP(dst=dns)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname,qtype="AAAA")))
        IPv6 = str(answer.an.rdata)
    return IPv6

def parser():
    parser = argparse.ArgumentParser(description='Query Google\'s DNS server for the IPv4 address of a hostname')
    parser.add_argument('-H', '--hostname',
                        dest='host',
                        help='Set hostname')
    parser.add_argument('-d', '--dns',
                        dest='dns',
                        help='Set DNS server')
    parser.add_argument('--ipv4',
                        dest='ipv4',
                        action='store_true')
    parser.add_argument('--ipv6',
                        dest='ipv6',
                        action='store_true')
    return parser.parse_args()

def main():
    args = parser()
    hostname = args.host
    dns = args.dns
    if dns == None:
        dns = '8.8.8.8'
    if args.ipv4:
        print(get_IPv4(hostname, dns))
    if args.ipv6:
        print(get_IPv6(hostname, dns))

if __name__ == "__main__":
    main()
