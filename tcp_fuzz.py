#!/usr/bin/python

from scapy.all import *
from time import sleep

while True:
  send(IP(dst='1.2.6.21')/fuzz(TCP(dport=4999)))
  sleep(1)

