## Import Scapy
from scapy.all import *

def sendShit(incomingPacket):	
	resultIP = IP(src=incomingPacket.payload.dst, dst=incomingPacket.payload.src)
	resultICMP = ICMP(type='echo-reply')
	resultRaw = Raw(load='THIS IS A PAYLOAD')
	packet = (resultIP/resultICMP/resultRaw)
	return packet

while(True):
	result = sniff(count=1)
	if(result[0].haslayer(ICMP)) and (result[0][ICMP].type == 8):
		send(sendShit(result[0]))
