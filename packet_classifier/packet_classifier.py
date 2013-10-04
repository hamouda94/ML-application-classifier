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
import numpy
from net.ip.ip_packet import IP_packet
from net.tcp.tcp_packet import TCP_packet 
from flows.flow_table import Flow_table
from filters.pkt_filter import Pkt_filter
from analyzer.pca.flow_pca import Flow_pca
from analyzer.logistic_reg.flow_log_regg import Flow_log_regg


if __name__=='__main__':
	#session table.
	print "Loading JSON %s" % (sys.argv[1])
	json_data = open(sys.argv[1])
	settings = json.load(json_data)
	ts = time.time()
	print 'start time :%f' % ts
	known_flow_table = Flow_table()
	unkown_flow_table = Flow_table()
	rt = time.time()
	pkt_filter = Pkt_filter("/home/asridharan/devsda5/Filter_output.json")
	bkgnd_sess = 0

	for pcap_file_key in settings["apps"].keys():
		#Create the pcap object
		p = pcap.pcapObject()
		#Open the dump file
		print "About to process signature for %s, from PCAP file %s" % (pcap_file_key, settings["apps"][pcap_file_key])
		p.open_offline(str(settings["apps"][pcap_file_key]))
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
				if (pcap_file_key != "unkown"):
					flow_table = known_flow_table
				else:
					flow_table = unkown_flow_table
				flow_entry = flow_table.update_flow_table(pkt_ip)
				#If the PCAP is the back-ground signature go ahead and update the flow entry blindly
				if ((pcap_file_key == "background") or (flow_entry.service == "")):
					flow_entry.service = pcap_file_key
					if (flow_entry.pkts == 1):
						bkgnd_sess += 1
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
						if (len(flow_entry.coeffs_dict["0"]) > flow_table.max_coeffs):
							flow_table.max_coeffs = len(flow_entry.coeffs_dict["0"])
			pkt = p.next()

	#Initialize the analyzer
	PCA = Flow_pca(known_flow_table, "0")
	PCA.normalize_and_scale()
	#flow_table.print_flow_table()

	#Generate decision vector
	i = 0
	Y = numpy.empty([len(known_flow_table.flow_table), 1], numpy.float)
	for flow_key in known_flow_table.flow_table.keys():
		Y[i] = (known_flow_table.flow_table[flow_key].service == "netflix")
		i += 1

	


	obj_LogReg = Flow_log_regg(known_flow_table, PCA.X, Y) 
	print "Created the logistic regression object"

	print "Creating the unknown sample matrix"
	PCA_unkown = Flow_pca(unkown_flow_table, "0")
	PCA_unkown.normalize_and_scale()

	#Make sure the number of features in the PCA_unkown matches the number of features PCA
	print "before shape:",PCA_unkown.X.shape
	if (PCA_unkown.X.shape[1] > (PCA.X.shape[1])):
			PCA_unkown.X = PCA_unkown.X[:,:PCA.X.shape[1]]
	print "after shape:",PCA_unkown.X.shape

	#Use the obj_LogReg to run a hypothesis test on each of the flow entry
	i = 0
	error = 0
	false_neg = 0
	samples = 0
	unknown_samples = 0
	unknown_bkgnd_sess = 0
	for flow_key in unkown_flow_table.flow_table.keys():
		samples += 1
		flow_entry = unkown_flow_table.flow_table[flow_key]
		Sample = numpy.array([PCA_unkown.X[i,:]])
		if flow_key in known_flow_table.flow_table.keys():
			flow_entry.service = known_flow_table.flow_table[flow_key].service
			if (flow_entry.service == "background"):
				unknown_bkgnd_sess += 1
		hypothesis = obj_LogReg.hypothesis(Sample)
		if (flow_entry.service == "unkown"):
			unknown_samples += 1
		if ((hypothesis < 0.5) and (flow_entry.service == "unkown")):
			false_neg += 1
		elif ((hypothesis > 0.5) and (flow_entry.service == "unkown")): 
			flow_entry.print_entry()
		i += 1
	te = time.time()
	print "unkown samples:%d, background samples:%d, samples:%d, unkwn bkgnd sess:%d, false_neg:%d" % \
		(unknown_samples, bkgnd_sess, samples, unknown_bkgnd_sess, false_neg)
	print 'Total time taken = %f sec' % (te-ts)

		



