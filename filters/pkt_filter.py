import pywt #wavelet library
import socket
import struct
import json
from flows.flow_table import Flow_table
from flows.flow_table import Flow_entry

class Pkt_filter:
	def __init__(self, out_filter_file, max_levels):
		self.ofd = open(out_filter_file, 'w')
		self.max_levels = max_levels
	def apply_filter(self,ip_packet, flow_entry):
		serialize_pkt = []
		if (ip_packet.version == 4):
			if (ip_packet.v4_packet.proto  == 6):
				payload_len = ip_packet.v4_packet.total_len - ip_packet.v4_packet.ihdl*4 - ip_packet.v4_packet.l4_packet.data_offset*4
				j = 0
				i = 0
				while (i < payload_len):
					if (i+1 < payload_len):
						serial_val = socket.ntohs(struct.unpack('B',ip_packet.v4_packet.l4_packet.tcp_payload[i:(i+1)])[0])
					else: 			
						if ( i < payload_len -1):
							serial_val = socket.ntohl(struct.unpack('B',ip_packet.v4_packet.l4_packet.tcp_payload[i:(payload_len)])[0])
						else:
							serial_val = ord(ip_packet.v4_packet.l4_packet.tcp_payload[payload_len - 1])
						break	
					serialize_pkt.append(serial_val)
					i += 1
				
				#apply the wavelet.
				if (len(serialize_pkt) > 0): 
					coeffs = pywt.wavedec(serialize_pkt, 'haar', level=self.max_levels)
					return coeffs
		return None		


	
