#!/usr/bin/python

from scapy.all import *

ROUTER_IP='192.168.1.1'
ROUTER_HW='9c:a9:e4:25:c8:ec'

def parse_arp_packet(p):
    if p[ARP].op==1: # who-has
        # algum client perguntando pelo MAC do gateway
        if p[ARP].pdst==ROUTER_IP:
            print '[+] possible client at ' + p[Ether].src + ' with IP ' + p[ARP].psrc

        # gateway querendo saber o MAC de um IP
        if p[ARP].hwsrc==ROUTER_HW and p[ARP].psrc==ROUTER_IP:
            if p[ARP].hwdst!='00:00:00:00:00:00':
                print '[+] possible client at ' + p[ARP].hwdst + ' with IP ' + p[ARP].pdst
            else:
                print '[-] possible client at ' + p[ARP].hwdst + ' with IP ' + p[ARP].pdst


sniff(filter='arp', prn=parse_arp_packet)
