import pywt #wavelet library
import socket
import struct
from flows.flow_table import Flow_table

class Pkt_filter:
	def apply_filter(self,ip_packet):
		serialize_pkt = []
		if (ip_packet.version == 4):
			if (ip_packet.v4_packet.proto  == 6):
				payload_len = ip_packet.v4_packet.total_len - ip_packet.v4_packet.ihdl*4 - ip_packet.v4_packet.l4_packet.data_offset*4
				j = 0
				i = 0
#				print "Payload len is: "+ str(payload_len)
				while (i < payload_len):
					if (i+2 < payload_len):
						serial_val = socket.ntohl(struct.unpack('H',ip_packet.v4_packet.l4_packet.tcp_payload[i:(i+2)])[0])
					else: 			
						if ( i < payload_len -1):
							serial_val = socket.ntohl(struct.unpack('H',ip_packet.v4_packet.l4_packet.tcp_payload[i:(payload_len)])[0])
						else:
							serial_val = ord(ip_packet.v4_packet.l4_packet.tcp_payload[payload_len - 1])
						break	
					serialize_pkt.append(serial_val)
					i += 2
					


	
