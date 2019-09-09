# tcp-experiments
A collection of small scapy scripts useful for TCP/IP network attacks.

There's an ICMP redirect example, used to redirect old OS IP stack to attacker machine, from phrack50, one to redirect Facebook's IP addresses and another from attacker choice. Tested and works even on switched network, but it depends on its configuration, if its configured to ignore ICMP type 5 the attack will not work.

There's also `find_connected_ips.py` useful to find connected IP(s) on airplanes, so you don't need to pay to use Internet, go on-line on someone's IP and MAC address =)
