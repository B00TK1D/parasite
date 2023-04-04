# Parasite

*Implants should be seen not heard*

Parasite is a tool for exfiltrating data from a network while blending in with pre-existing traffic.  It reads in a pcap of a target network, analyzes the data, and generates a client python script which can be used to exfiltrate data from the network.

Usage: `parasite.py <pcap> <server-ip> <listen-interface> [secret-key]`

Example: `python3 parasite.py test17.pcapng 127.0.0.1 lo0`

Run client.py on the target network to exfiltrate data, it will read data from stdin and send it to the server which outputs it to stdout.