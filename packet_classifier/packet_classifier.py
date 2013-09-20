#The code has been borrowed from pylibpcap.sourceforge.net
import pcap,os
import sys
import string
import time
import socket
import struct
import operator
import pywt
import time
import json
from net.ip.ip_packet import IP_packet
from net.tcp.tcp_packet import TCP_packet 
from flows.flow_table import Flow_table
from filters.pkt_filter import Pkt_filter
from analyzer.pca.flow_pca import Flow_pca


if __name__=='__main__':
	#session table.
	json_data = open('settings.json')
	app_signature = json.load(json_data)
	ts = time.time()
	print 'start time :%f' % ts
	flow_table = Flow_table()
	rt = time.time()
	pkt_filter = Pkt_filter("/home/asridharan/devsda5/Filter_output.json")

	for pcap_file_key in app_signature["apps"].keys():
		#Create the pcap object
		p = pcap.pcapObject()
		#Open the dump file
		print "About to process signature for %s, from PCAP file %s" % (pcap_file_key, app_signature["apps"][pcap_file_key])
		p.open_offline(str(app_signature["apps"][pcap_file_key]))
		pkt = p.next()
		while (pkt != None):
			length= pkt[0]
			if (length == 0):
				print "found 0 length packet"
				break
			data = pkt[1]
			time_stamp = pkt[2]
			if data[12:14]=='\x08\x00':
				pkt_ip = IP_packet(data[14:])
			if (pkt_ip.version == 4):
				flow_entry = flow_table.update_flow_table(pkt_ip)
				#If the PCAP is the back-ground signature go ahead and update the flow entry blindly
				if ((pcap_file_key == "background") or (flow_entry.service == "")):
					flow_entry.service = pcap_file_key
				if (flow_entry.pkts < 20):
					#apply the packet filter only for the first 1MB of traffic
					#We can change this to a certain number of packets.
					coeffs = pkt_filter.apply_filter(pkt_ip, flow_entry.flow_key)
					if (coeffs != None):
						for i in range(0,22):
							if (str(i) not in flow_entry.coeffs_dict.keys()):
								flow_entry.coeffs_dict[str(i)] = coeffs[i].tolist()
							else: 
								(flow_entry.coeffs_dict[str(i)]).extend(coeffs[i].tolist())
						if (len(flow_entry.coeffs_dict["21"]) > flow_table.max_coeffs):
							flow_table.max_coeffs = len(flow_entry.coeffs_dict["21"])
			pkt = p.next()

	#Initialize the analyzer
	PCA = Flow_pca(flow_table)
	PCA.perform_pca()
	#flow_table.print_flow_table()
	te = time.time()
	print 'Total time taken = %f sec' % (te-ts)

		



