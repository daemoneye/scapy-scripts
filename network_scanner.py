#!/usr/bin/env python3
import argparse
from scapy.all import *

def query(target_ip):
    local_mac = getmacbyip("127.0.0.1")
    arp       = ARP(pdst=target_ip)
    ether     = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet    = ether/arp
    clients   = []

    # Quietly get the results
    result  = srp(packet, timeout=3, verbose=0)[0]

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Reset own MAC address
    Ether(dst=mac)

    return clients

def arguments():
    parser = argparse.ArgumentParser(description=
            'Query a DNS server for the IPv4 address of a hostname')
    parser.add_argument(dest='target',
                        help='Specify a target IP')
    return parser.parse_args()

def main():
    args = arguments()
    clients = query(args.target)
    print("Available devices:")
    print("IP" + " "*18 + "MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

if __name__ == "__main__":
    main()
