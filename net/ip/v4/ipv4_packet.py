import string
import socket
import struct
import pcap
from net.tcp.tcp_packet import TCP_packet 
from net.udp.udp_packet import UDP_packet 

class IPv4_packet:
	def __init__(self, s):
	#Decoding the IP packet
		self.version=(ord(s[0]) & 0xf0) >> 4
		self.ihdl=ord(s[0]) & 0x0f
		self.tos=ord(s[1])
		self.total_len=socket.ntohs(struct.unpack('H',s[2:4])[0])
		self.ident=socket.ntohs(struct.unpack('H',s[4:6])[0])
		self.flags=(ord(s[6]) & 0xe0) >> 5
		self.frag_offset=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
		self.ttl=ord(s[8])
		self.proto=ord(s[9])
		self.csum=socket.ntohs(struct.unpack('H',s[10:12])[0])
		self.src_ip=pcap.ntoa(struct.unpack('i',s[12:16])[0])
		self.dest_ip=pcap.ntoa(struct.unpack('i',s[16:20])[0])
		if self.ihdl > 5:
			self.options=s[20:4*(self.ihdl-5)]
		else:
			self.options=None
		self.l4_payload=s[4*self.ihdl:]
		#Create an object based on the payload.
		if (self.proto == 6): 
			self.l4_packet = TCP_packet(self.l4_payload)
		if (self.proto == 17): 
			self.l4_packet = UDP_packet(self.l4_payload)
