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
        answer = sr1(IP(dst=dns)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname,qtype=record)), verbose=0)
        ADDR = answer.an.rdata
    return ADDR

def send_msg(address, message):
    send(IP(dst=address)/ICMP()/message)

def parser():
    parser = argparse.ArgumentParser(description='Send a message to another machine via ICMP')
    parser.add_argument('-H', '--hostname',
                        dest='host',
                        required=True,
                        help='Set hostname')
    parser.add_argument('-m', '--message',
                        dest='message',
                        help='Set message to be sent')
    parser.add_argument('-d', '--dns',
                        dest='dns',
                        help='Set DNS server')
    return parser.parse_args()

def main():
    args = parser()
    hostname = args.host
    message = args.message
    dns = args.dns

    if dns == None:
        dns = '8.8.8.8'

    if message == None:
        message = input("Enter the message you want to send: ")

    if os.geteuid() == 0:
        IPv4 = get_IP(hostname, dns, "A")
        IPv6 = get_IP(hostname, dns, "AAAA")
    else:
        exit("Script needs to be run as root user")

if __name__ == "__main__":
    main()
