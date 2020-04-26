#!/usr/bin/env python3
from scapy.all import *

def get_IPv4(hostname):
    IPv4 = ''
    if hostname == 'localhost':
        IPv4 = '127.0.0.1'
    else:
        answer = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname,qtype="A")))
        IPv4 = str(answer.an.rdata)
    return IPv4

def main():
    address1 = "localhost"
    address2 = "www.daemo.nz"
    
    print(address2 + " = " + get_IPv4(address2))
    print(address1 + " = " + get_IPv4(address1))

if __name__ == "__main__":
    main()
