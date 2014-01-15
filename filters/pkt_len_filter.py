import dpkt

class Pkt_len_filter:
	def apply_filter(self,ip_packet):
		payload_len = 0
		if (ip_packet.p  == dpkt.ip.IP_PROTO_TCP):
			payload_len = ip_packet.len - ip_packet.hl*4 - ip_packet.data.off*4
			#payload_len |= (ip_packet.v4_packet.l4_packet.tcp_flags << 16) 

		if (ip_packet.p == dpkt.ip.IP_PROTO_UDP):
			#UDP header length 8 bytes
			payload_len = ip_packet.data.ulen - 8
		return payload_len


	
