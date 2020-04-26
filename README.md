# Scapy Scripts
This will be a collection of scripts I create around the [Scapy](https://scapy.net/) Python Library. These scripts will become more complex as I learn the Library.

## DNS.py
dns.py is my first attempt at writing a script using Scapay. The goal is to be able to customize a query to a DNS server without having to change system settings.

dns.py needs to be run as root.

Options for usage:

usage: dns.py [-h] -H HOST [-d DNS] [--ipv4] [--ipv6]

Query a DNS server for the IPv4 address of a hostname

optional arguments:

  -h, --help            show this help message and exit

  -H HOST, --hostname HOST Set hostname

  -d DNS, --dns DNS     Set DNS server

  --ipv4                Get IPv4 address

  --ipv6                Get IPv6 address

## Authors
Keane Wolter - dns.py

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
