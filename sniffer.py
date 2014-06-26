## Import Scapy
from scapy.all import *

## Called when a packet is sniffed
def seeend(*args):
	send(IP(src='129.170.210.222', dst='129.170.210.76')/ICMP(type='echo-request')/Raw(load='PAYLOAD GOES HERE'))

## Setup sniff by filtering for ICMP and respond using packetRespond function
sniff(filter="icmp and host 129.170.210.76", prn=seeend)
