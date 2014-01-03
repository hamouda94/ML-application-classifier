from flows.flow_table import Flow_table
from flows.flow_table import Flow_entry

class Pkt_len_filter:
	def apply_filter(self,ip_packet, flow_entry):
		payload_len = 0
		if (ip_packet.version == 4):
			if (ip_packet.v4_packet.proto  == 6):
				payload_len = ip_packet.v4_packet.total_len - ip_packet.v4_packet.ihdl*4 - ip_packet.v4_packet.l4_packet.data_offset*4
				#payload_len |= (ip_packet.v4_packet.l4_packet.tcp_flags << 16) 

			if (ip_packet.v4_packet.proto == 17):
				#UDP header length 8 bytes
				payload_len = ip_packet.v4_packet.l4_packet.udp_payload_length
		return payload_len


	
