#The code has been borrowed from pylibpcap.sourceforge.net
import pcap,os
import sys
import string
import time
import socket
import struct

#Decoding an IP packet
def decode_ip_packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d


if __name__=='__main__':
	#Create the pcap object
	p = pcap.pcapObject()
	#Open the dump file
	p.open_offline('/Users/asridharan/netflix_dump.pcap')
	i = 0
	total_len = 0
	while 1:
		i +=1
		try:
			#p.next() returns a 3 tuple. Length, Data, Time stamp
			pkt = p.next()
			length= pkt[0]
			total_len +=length
			data = pkt[1]
			time_stamp = pkt[2]
			if data[12:14]=='\x08\x00':
				pkt_ip = decode_ip_packet(data[14:])
				#dump the decoded IP packet
				#print "Version:"+str(pkt_ip['version'])+'\t'
				#print "Protocol:"+str(pkt_ip['protocol'])+'\t'
				#print "Source Address:"+str(pkt_ip['source_address'])+'\t'
				#print "Destination Addres:"+str(pkt_ip['destination_address'])+'\n'
		except TypeError:
			print "Reached end of file, total packets:" + str(i)+"Total length:"+str(total_len)
			break



