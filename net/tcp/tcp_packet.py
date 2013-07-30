import string
import socket
import struct
import operator
class TCP_packet:
	def __init__(self, ip_payload):
		try:
			self.src_port = socket.ntohs(struct.unpack('H',ip_payload[0:2])[0])
		except TypeError:
			print "ERROR retrieving TCP source port!!"
		try:
			self.dest_port = socket.ntohs(struct.unpack('H', ip_payload[2:4])[0])
		except TypeError:
			print "ERROR retrieving TCP dest port!!"
		self.data_offset = (ord(ip_payload[12]) & 0xf0) >> 4 
		self.tcp_payload = ip_payload[(self.data_offset*4):]
