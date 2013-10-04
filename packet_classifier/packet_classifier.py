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
	print "Loading JSON %s" % (sys.argv[1])
	json_data = open(sys.argv[1])
	settings = json.load(json_data)
	ts = time.time()
	print 'start time :%f' % ts

	#session table, for known and unknown
	known_flow_table = Flow_table()
	unknown_flow_table = Flow_table()
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
				if (pcap_file_key != "unknown"):
					flow_table = known_flow_table
				else:
					flow_table = unknown_flow_table
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

	#Initialize the PCA object
	PCA = Flow_pca(known_flow_table, "0")
	PCA.normalize_and_scale()
	#flow_table.print_flow_table()

	#Generate decision vector
	i = 0
	Y = numpy.empty([len(known_flow_table.flow_table), 1], numpy.float)
	for flow_key in known_flow_table.flow_table.keys():
		Y[i] = (known_flow_table.flow_table[flow_key].service == "skype")
		i += 1

	


	obj_LogReg = Flow_log_regg(known_flow_table, PCA.X, Y) 
	print "Created the logistic regression object"

	#Create the PCA object for the unknown samples
	print "Creating the unknown sample matrix"
	PCA_unknown = Flow_pca(unknown_flow_table, "0")
	PCA_unknown.normalize_and_scale()

	#Make sure the number of features in the PCA_unknown matches the number of features PCA
	print "before shape:",PCA_unknown.X.shape
	if (PCA_unknown.X.shape[1] > (PCA.X.shape[1])):
			PCA_unknown.X = PCA_unknown.X[:,:PCA.X.shape[1]]
	print "after shape:",PCA_unknown.X.shape

	#Use the obj_LogReg to run a hypothesis test on each of the flow entry
	i = 0
	error = 0
	false_neg = 0
	samples = 0
	unknown_samples = 0
	unknown_bkgnd_sess = 0
	#open file to log classified entries
	cl_fd = open(settings["files"]["classified"],"w")
	uncl_fd = open(settings["files"]["un-classified"],"w")
	#open file to log un-classified entries
	for flow_key in unknown_flow_table.flow_table.keys():
		samples += 1
		flow_entry = unknown_flow_table.flow_table[flow_key]
		Sample = numpy.array([PCA_unknown.X[i,:]])
		if flow_key in known_flow_table.flow_table.keys():
			flow_entry.service = known_flow_table.flow_table[flow_key].service
			if (flow_entry.service == "background"):
				unknown_bkgnd_sess += 1
		flow_entry.hypothesis = obj_LogReg.hypothesis(Sample)
		if (flow_entry.service == "unknown"):
			unknown_samples += 1
		if ((flow_entry.hypothesis < 0.45) and (flow_entry.service == "unknown")):
			#unclassified
			flow_entry.print_entry(uncl_fd)
		elif ((flow_entry.hypothesis > 0.45) and (flow_entry.service == "unknown")): 
			#classified
			flow_entry.print_entry(cl_fd)
			false_neg += 1
		i += 1
	te = time.time()
	print "unknown samples:%d, background samples:%d, samples:%d, unkwn bkgnd sess:%d, false_neg:%d" % \
		(unknown_samples, bkgnd_sess, samples, unknown_bkgnd_sess, false_neg)
	print 'Total time taken = %f sec' % (te-ts)

		



