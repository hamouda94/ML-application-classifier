import dpkt
import os
import sys
import json
import numpy 
from optparse import OptionParser
from flows.flow_table import Flow_table
from filters.pkt_len_filter import Pkt_len_filter
from analyzer.pca.flow_pca import Flow_pca

#main function
if __name__=='__main__':
	print
	"===========================Initialization===================================="
	parser = OptionParser(usage="%prog <settings JSON>")

	(parse_options, args) = parser.parse_args()	
	if len(args) != 1:
		parser.error("Incorrect number of arguments")
	print "Opening JSON file %s" %(args[0])
	json_data = open(args[0])
	#Learn the applications from the input JSON file
	service_id = {}#{'netflix':1,'gmail':1, 'background':1}
	org_settings = json.load(json_data)
	apps = org_settings["apps"];
	max_levels = org_settings["max_levels"]  
	level_steps = org_settings["level_steps"]
	SUT = None
	print "Analysing the application found in %s" % (args[0])
	for keys in apps:
		service_id[keys] = 1
		print "Found app:%s" % (keys)
	#Initialize the flow table
	pkt_flow_table = Flow_table(1)
	#the packet filter, used for feature extraction on a packet.
	pkt_filter = Pkt_len_filter()

	#Parse the PCAP files and generate the statistics of the packets within a
	#PCAP file.
	for pcap_file_key in org_settings["apps"]:
		for idx in range(0,len(org_settings["apps"][pcap_file_key])):
			pcap_file = open(org_settings["apps"][pcap_file_key][idx], "r")
			print "Processing PCAP file for service %s:%s" % (pcap_file_key, org_settings["apps"][pcap_file_key][idx])
			for tx, pkt in dpkt.pcap.Reader(pcap_file):
				#process the packet, generate coeffecients and update the flow 
				#table.
				pkt_flow_table.process_pkt(pkt=pkt, \
					pkt_filter=pkt_filter, service=pcap_file_key,\
					sample_idx=idx, max_levels=max_levels)
			pcap_file.close()

	
	print "====================Creating PCA objects (Supervised)=============================="		
	PCA = Flow_pca(pkt_flow_table, service_id, SUT, str(0))
	#Calculate the mean of each row of the PCA.
	mu = numpy.mean(PCA.X, axis = 1)
	var = numpy.var(PCA.X, axis = 1)
	#open a data file for each of the services
	out_fd = {}
	for services in service_id:
		file_name = services+".dat"
		out_fd[services] = open(file_name,"w") 
		
	for i in range(0, len(mu)):
		out_str=str(mu[i])+" "+str(var[i])+"\n"
		out_fd[PCA.L[i]].write(out_str)





