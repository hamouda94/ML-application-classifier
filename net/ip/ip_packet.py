from net.ip.v4.ipv4_packet import IPv4_packet 

class IP_packet:
	def __init__(self, s):
		try:
			self.version=(ord(s[0]) & 0xf0) >> 4
			if (self.version == 4):
				try:
					self.v4_packet=IPv4_packet(s)
				except TypeError:
					print "Unable to create the IP v4 packet."
		except TypeError:
			print "Unable to create the IP packet."

