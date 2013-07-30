import string
import operator
import sys

class Flow_table:
	def __init__(self):
		self.flow_table = {} 

	def update_flow_table(self, ip_packet):
		try:
			flow_key = str(ip_packet.version)+"|"+str(ip_packet.v4_packet.src_ip)+"|"+str(ip_packet.v4_packet.dest_ip)
		except AttributeError:
			print "Unknown attribute found in ip_packet!!"
			return
		try:
			if ip_packet.v4_packet.proto == 6:
				flow_key = flow_key + "|TCP"+"|" + str(ip_packet.v4_packet.l4_packet.src_port) + "|" + str(ip_packet.v4_packet.l4_packet.dest_port)
			elif ip_packet.v4_packet.proto == 17:
				flow_key = flow_key + "|UDP"
		except AttributeError:
			print "Unknown attribute found in ip_packet, while setting the protocol!!"
			return
		#use the flow_key to access the dictionary
		try:
			self.flow_table[flow_key] = self.flow_table[flow_key] + ip_packet.v4_packet.total_len
		except KeyError:
			#initialize the flow_key entry in the flow_table
			self.flow_table[flow_key] = ip_packet.v4_packet.total_len

	def print_table(self):
		sorted_flow_table = sorted(self.flow_table.iteritems(), key=operator.itemgetter(1))
		for flow_entry_value in sorted_flow_table:
			print flow_entry_value
		print 'Total sessions:',len(self.flow_table)
