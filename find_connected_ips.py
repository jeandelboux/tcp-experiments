#!/usr/bin/python
#
# TODO:
# 1-automatically detect if MAC/IP is connected to Internet
# 2-print commands to user ctrl+c/v set to its interface
# 3-automaticall set interfaces IP, MAC and router
#

from scapy.all import *

def parse_arp_packet(p):
    if p[ARP].op==1: # who-has
        # client is asking for gateway MAC address (by its IP address)
        if p[ARP].pdst==ROUTER_IP:
            print '[+] possible client at ' + p[Ether].src + ' with IP ' + p[ARP].psrc

        # gateway is asking for client MAC address (by its IP address) broadcasting at L2
        if p[ARP].hwsrc==ROUTER_HW and p[ARP].psrc==ROUTER_IP and p[Ether].dst=='ff:ff:ff:ff:ff:ff':
            if p[ARP].hwdst!='00:00:00:00:00:00':
                # gateway is asking for myself, probably my machine is not arp replying
                print '[+] possible client at ' + p[ARP].hwdst + ' with IP ' + p[ARP].pdst + ' (myself?)' # if not myself how could this happened?!
            else: # ok this is normal since it won't be expected to receive others L2 packets
                print '[+] ping this shit to know MAC address of this IP:  ' + p[ARP].pdst

if len(sys.argv)!=4:
   print "Detect clients connected to LAN, so that you can assign your interface to its"
   print "MAC address and assign its IP, then you'll have same access in the LAN."
   print "To test the MAC and IP you'll have to:"
   print "sudo ifconfig [interface-name] down"
   print "sudo ifconfig [interface-name] hw ether [MAC address]"
   print "sudo ifconfig [interface-name] [IP address]"
   print "sudo route add default gw [router-ip]"
   print "Usage:", sys.argv[0], "[interface-name] [router-IP-address] [router-MAC-address]"
   exit(1)

#conf.ipv6_enabled=False
conf.iface=sys.argv[1]
ROUTER_IP=sys.argv[2]
ROUTER_HW=sys.argv[3]

print '[+] waiting for useful ARP packets...'
sniff(filter='arp', prn=parse_arp_packet)
