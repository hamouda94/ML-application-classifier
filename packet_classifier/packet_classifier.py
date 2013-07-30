#The code has been borrowed from pylibpcap.sourceforge.net
import pcap,os
import sys
import string
import time
import socket
import struct
import operator
import pywt
from net.ip.ip_packet import IP_packet
from net.tcp.tcp_packet import TCP_packet 
from flows.flow_table import Flow_table
from filters.pkt_filter import Pkt_filter


if __name__=='__main__':
	#session table.
	flow_table = Flow_table()
	#Create the pcap object
	p = pcap.pcapObject()
	pkt_filter = Pkt_filter()
	#Open the dump file
	p.open_offline('/Users/asridharan/netflix_24Jul2013.pcap')
	pkt = p.next()
	while (pkt != None):
		length= pkt[0]
		if (length == 0):
			print "found 0 length packet"
			break
		data = pkt[1]
		time_stamp = pkt[2]
		print time_stamp
		if data[12:14]=='\x08\x00':
			pkt_ip = IP_packet(data[14:])
		if (pkt_ip.version == 4):
			flow_table.update_flow_table(pkt_ip)
			pkt_filter.apply_filter(pkt_ip)

		pkt = p.next()

	flow_table.print_table()

		



