import string
import operator
import sys
import time
from net.ip.ip_packet import IP_packet

class Flow_entry:
	def __init__(self, flow_key):
		self.flow_key = flow_key
		self.total_len = 0
		self.st = time.time() #Start time of window
		self.rt = self.st #run time of window
		self.run_bytes = 0 #running bytes measured in the last time-window
		self.rate = 0.0
		self.coeffs_dict = {}
		self.dimension = -1
		self.dimension_val = 0.0
		self.service = ""
		self.pkts = 0

	def update_rate(self, pkt_bytes):
		self.run_bytes += pkt_bytes
		self.rt = time.time()
		if ((self.rt - self.st) > 1.0):
			#update the rate in bps since the 1sec window has elapsed.
			tmp_bps = (self.run_bytes*8)/(self.rt - self.st)
			#maintain the exponential moving average of the rate.
			self.rate = 0.8*self.rate + 0.2*tmp_bps
			self.run_bytes = 0
			self.st = self.rt

	def print_entry(self):
		if ("21" in self.coeffs_dict.keys()):
			length = len(self.coeffs_dict["21"])
		else:
			length = 0
		print '%s: rate:%f bits/sec, total bytes:%d bytes approx coeff:%d, dimension:%d, corr_dim:%f, service:%s' \
			% (self.flow_key, self.rate, self.total_len, length, self.dimension, self.dimension_val, self.service)



class Flow_table:
	def get_sortable_key(self, flow_item):
		f = operator.itemgetter(1)
		flow_entry = f(flow_item)
		return flow_entry.total_len
	def __init__(self):
		self.flow_table = {} 
		self.max_coeffs = 0;
		self.big_hitters = {}

	def gen_flow_key(self, ip_packet):
		try:
			flow_key = str(ip_packet.version)+"|"+str(ip_packet.v4_packet.src_ip)+"|"+str(ip_packet.v4_packet.dest_ip)
		except AttributeError:
			print "Unknown attribute found in ip_packet!!"
			return None
		try:
			if (ip_packet.v4_packet.proto == IP_packet.protocols['tcp']):
				flow_key += "|TCP"+"|" + str(ip_packet.v4_packet.l4_packet.src_port) + "|" + str(ip_packet.v4_packet.l4_packet.dest_port)
			elif (ip_packet.v4_packet.proto == IP_packet.protocols['udp']):
				flow_key += "|UDP"
		except AttributeError:
			print "Unknown attribute found in ip_packet, while setting the protocol!!"
			return None
		return flow_key

	def update_flow_table(self, ip_packet):
		flow_key = self.gen_flow_key(ip_packet)
		#use the flow_key to access the dictionary
		if (flow_key in self.flow_table):
			flow_entry = self.flow_table[flow_key]
			flow_entry.total_len  +=  ip_packet.v4_packet.total_len
			self.big_hitters[flow_key] += ip_packet.v4_packet.total_len
			flow_entry.pkts += 1
		else:
			flow_entry = Flow_entry(flow_key)
			self.flow_table[flow_key] = flow_entry
			flow_entry.total_len = ip_packet.v4_packet.total_len
			flow_entry.pkts += 1
			self.big_hitters[flow_key] = ip_packet.v4_packet.total_len

		flow_entry.update_rate(ip_packet.v4_packet.total_len)
		return flow_entry

	def print_flow_table(self):
		sorted_flow_entry_tupples  = sorted(self.flow_table.iteritems(), key=self.get_sortable_key)
		for flow_entry_tupple in sorted_flow_entry_tupples:
			flow_entry_tupple[1].print_entry()

