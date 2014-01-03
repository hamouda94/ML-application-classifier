import string
import socket
import struct
import operator
class UDP_packet:
	def __init__(self, ip_payload):
		try:
			self.src_port = socket.ntohs(struct.unpack('H',ip_payload[0:2])[0])
		except TypeError:
			print "ERROR retrieving UDP source port!!"
		try:
			self.dest_port = socket.ntohs(struct.unpack('H', ip_payload[2:4])[0])
		except TypeError:
			print "ERROR retrieving UDP dest port!!"
		self.udp_payload_length = socket.ntohs(struct.unpack('H',ip_payload[4:6])[0])  - 8
		self.udp_payload = ip_payload[8:]
