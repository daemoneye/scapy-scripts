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

def is_ip(address):
    isIP = True
    split = address.split('.')
    for each in split:
        for char in each:
            if char.isalpha():
                isIP = False
    return isIP

def send_msg(address, message):
    send(IP(dst=address)/ICMP()/message, verbose=0)

def parser():
    parser = argparse.ArgumentParser(description='Send a message to another machine via ICMP')
    parser.add_argument(dest='host',
                        type=str,
                        help='Set hostname')
    parser.add_argument('-m', '--message',
                        dest='message',
                        type=str,
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

    if os.geteuid() != 0:
        exit("Script needs to be run as root user")

    if message == None:
        message = input("Enter the message you want to send: ")

    if is_ip(hostname) == False:
        IPv4 = get_IP(hostname, dns, "A")
    else:
        IPv4 = hostname

    send_msg(IPv4, message)

if __name__ == "__main__":
    main()
