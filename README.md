# Scapy Scripts
This will be a collection of scripts I create around the [Scapy](https://scapy.net/) Python Library. These scripts will become more complex as I learn the Library.

## DNS.py
dns.py is my first attempt at writing a script using Scapay. The goal is to be able to customize a query to a DNS server without having to change system settings.

dns.py needs to be run as root.

### Options for usage:

optional arguments:

  -h, --help            show this help message and exit

  -H HOST, --hostname HOST Set hostname

  -d DNS, --dns DNS     Set DNS server

  --ipv4                Get IPv4 address

  --ipv6                Get IPv6 address

## icmp\_message.py
icmp\_message.py is a script to demonstrate how to send an ICMP message to a given IP address. Like DNS.py, this script needs to be run as root.

### Options for usage:

optional arguments:

  -h, --help            show this help message and exit

  -H HOST, --hostname HOST Set hostname

  -m MESSAGE, --message MESSAGE Set message to be sent

  -d DNS, --dns DNS     Set DNS server

## interface\_info.py
interface\_info.py is a tool to simply inform you of the IP and MAC addresses for all interfaces on the machine it is running on.

## network\_scanner.py
The network\_scanner.py script will scan an IP range and return all active IP addresses with the appropriate MAC address. The only flag that is required is the IP address range in CIDR notation.

## Authors
Keane Wolter - dns.py, icmp\_message.py, interface\_info.py, network\_scanner.py

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
