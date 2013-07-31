import string
import operator
import sys
from net.ip.ip_packet import IP_packet

class Flow_entry:
	def __init__(self, ip_packet):
		try:
			self.flow_key = str(ip_packet.version)+"|"+str(ip_packet.v4_packet.src_ip)+"|"+str(ip_packet.v4_packet.dest_ip)
		except AttributeError:
			print "Unknown attribute found in ip_packet!!"
			return
		try:
			if (ip_packet.v4_packet.proto == IP_packet.protocols['tcp']):
				self.flow_key += "|TCP"+"|" + str(ip_packet.v4_packet.l4_packet.src_port) + "|" + str(ip_packet.v4_packet.l4_packet.dest_port)
			elif (ip_packet.v4_packet.proto == IP_packet.protocols['udp']):
				self.flow_key += "|UDP"
		except AttributeError:
			print "Unknown attribute found in ip_packet, while setting the protocol!!"
			return
		self.total_len = 0

class Flow_table:
	def __init__(self):
		self.flow_table = {} 
		self.big_hitters = {}

	def update_flow_table(self, ip_packet):
		flow_entry = Flow_entry(ip_packet)
		#use the flow_key to access the dictionary
		if (flow_entry.flow_key in self.flow_table):
			self.flow_table[flow_entry.flow_key].total_len  +=  ip_packet.v4_packet.total_len
			self.big_hitters[flow_entry.flow_key] += ip_packet.v4_packet.total_len
		else:
			self.flow_table[flow_entry.flow_key] = flow_entry
			flow_entry.total_len = ip_packet.v4_packet.total_len
			self.big_hitters[flow_entry.flow_key] = ip_packet.v4_packet.total_len

	def print_big_hitters(self):
		sorted_big_hitters = sorted(self.big_hitters.iteritems(), key=operator.itemgetter(1))
		for  big_hitters_value in sorted_big_hitters:
			print big_hitters_value
		print 'Total sessions:',len(self.big_hitters)
