#!/usr/bin/env python3
import argparse
from scapy.all import *

def get_IPv4(hostname):
    IPv4 = ''
    
    # Localhost is always 127.0.0.1
    if hostname == 'localhost':
        IPv4 = '127.0.0.1'
    else:
        answer = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname,qtype="A")))
        IPv4 = str(answer.an.rdata)
    return IPv4

def parser():
    parser = argparse.ArgumentParser(description='Query Google\'s DNS server for the IPv4 address of a hostname')
    parser.add_argument('-H', '--hostname',
                        dest='host',
                        help='Set hostname')
    return parser.parse_args()

def main():
    args = parser()
    print(get_IPv4(args.host))

if __name__ == "__main__":
    main()
