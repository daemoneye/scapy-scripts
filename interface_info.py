#!/usr/bin/env python3
from scapy.all import *

for each in get_if_list():
    ip = get_if_addr(each)
    mac = get_if_hwaddr(each)
    print("Interface " + str(each) + " has an IP address of " + str(ip) + " and a MAC address of " + str(mac))
