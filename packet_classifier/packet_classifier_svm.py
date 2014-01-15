#The code has been borrowed from pylibPCAp.sourceforge.net
import dpkt,os
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
from PyML import *
from optparse import OptionParser
from net.ip.ip_packet import IP_packet
from net.tcp.tcp_packet import TCP_packet 
from flows.flow_table import Flow_table
from filters.pkt_len_filter import Pkt_len_filter
from analyzer.pca.flow_pca import Flow_pca
from analyzer.logistic_reg.flow_log_regg import Flow_log_regg
#process_pkt:
#	Parses the packet read from the PCAP file, creates a flow_entry, if already
# 	not present, and generates coefficients for the given packet.
#	pkt: The packet to be processed.
#	known_flow_table: The flow table object containing all the known
#					  flows. This will be used when we are going to 
#					  learn new parameters for our	classification.
#	unknown_flow_table: The flow table object containing all the unknown 
#					  flows. 
def process_pkt(pkt, known_flow_table, unknown_flow_table, pkt_filter, service,\
				sample_idx, max_levels):
	pkt_ip = None
	pkt_eth = dpkt.ethernet.Ethernet(pkt)	
	if pkt_eth.type == dpkt.ethernet.ETH_TYPE_IP:
		pkt_ip = pkt_eth.data
	else:
		print "Found a non-IP packet"
		return 
	if (service != "unknown"):
		flow_table = known_flow_table
	else:
		flow_table = unknown_flow_table
	#A flow entry is basically a sample interaction between a client
	#a service. A service is defined by a server IP, and a port.
	#By a sample, we mean all interactions of the client with this service
	#in this PCAP file. So if a client was having the same interaction, with
	# the service, in a different PCAP file, it would be considered a new
	# sample
	flow_entry = flow_table.update_flow_table(pkt_ip, service, sample_idx)
	if (flow_entry == None):
		#Couldn't create the flow_entry, just return
		return
	if (flow_entry.pkts > 10000):
		#We don't need more than 10000 features for a given 
		#flow
		return

	#apply the packet filter only 
	plength = pkt_filter.apply_filter(pkt_ip)
	#we are using the packet length filter, so set max_levels to 1.
	#TODO: The concept of max-levels made sense when we using wavelets. 
	#With packet lengths, max-levels doesn't make much sense. Though, it
	#make sense if use max-levels to denote the different metrics that we 
	#plan to use for a given flow-entry, for e.g. use inter-arrival times
	#along with packet length.
	for i in range(0, max_levels):
		if str(i) not in flow_entry.coeffs_dict:
			flow_entry.coeffs_dict[str(i)] = []
		else: 
			(flow_entry.coeffs_dict[str(i)]).append(plength)
		if (len(flow_entry.coeffs_dict[str(i)]) > flow_table.max_coeffs[i]):
			flow_table.max_coeffs[i] = len(flow_entry.coeffs_dict[str(i)])

def perform_classification(service_id, settings, SUT, options):
	max_levels = settings["max_levels"]  
	level_steps = settings["level_steps"]
	PCA = [None for x in range(0, max_levels)]

	#session table, for known and unknown
	known_flow_table = Flow_table(max_levels)
	unknown_flow_table = Flow_table(max_levels)


	#the packet filter, used for feature extraction on a packet.
	pkt_filter = Pkt_len_filter()
	ts = time.time()
	print 'start time :%f' % ts

	print "====================Processing PCAP=============================="		
	#PCAp file processing....
	for pcap_file_key in settings["apps"]:
		#if we don't need to learn the parameters read only the unknown PCAp
		#file.
		#note: 
		if (pcap_file_key != "unknown" and options.learn == False):
			print "already have parameters for service %s, not reading PCAp"\
						" file"  % (pcap_file_key)
			continue
		#create the PCAp object
		for idx in range(0,len(settings["apps"][pcap_file_key])):
			pcap_file = open(settings["apps"][pcap_file_key][idx], "r")
			print "Processing PCAP file %s" % (settings["apps"][pcap_file_key][idx])
			for tx, pkt in dpkt.pcap.Reader(pcap_file):
				#process the packet, generate coeffecients and update the flow 
				#table.
				process_pkt(pkt=pkt, known_flow_table = known_flow_table,\
					unknown_flow_table = unknown_flow_table, \
					pkt_filter=pkt_filter, service=pcap_file_key,\
					sample_idx=idx, max_levels=max_levels)
			pcap_file.close()
	print "====================Processing PCAP done=============================="		


	print "====================Creating PCA objects (Supervised)=============================="		
	#initialize the PCA object
	if (options.learn == True):
		print "we need to learn/re-learn the theta parameters"
		for detail_coeff in level_steps:
			PCA[detail_coeff] = Flow_pca(known_flow_table, service_id, SUT, str(detail_coeff))
			PCA[detail_coeff].normalize_and_scale()
	print "====================PCA object creation done (Supervised)=============================="		


	#generate logistic reg parameters for each of the different services
	rewrite_param_json = False
	svm_data=[None]* len(level_steps)
	svm_classifier =[None]* len(level_steps)
	if (options.learn == True):
		print "====================Creating SVM objects=============================="		
		for detail_coeff in level_steps:
			svm_data[detail_coeff] = VectorDataSet(PCA[detail_coeff].X, L = PCA[detail_coeff].L)
			print svm_data[detail_coeff]
			print "Number of features:%d" % (svm_data[detail_coeff].numFeatures)
			#use a guassian kernel on this data
			svm_data[detail_coeff].attachKernel('gaussian', gamma = 4)
			svm_classifier[detail_coeff] = SVM(C=1000)
			svm_classifier[detail_coeff].train(svm_data[detail_coeff])
			#lets look at the cross validations of the data
			print "==========performing cross validation========"
			svm_result = svm_classifier[detail_coeff].cv(svm_data[detail_coeff])
			print"Success Rate:%f"% (svm_result.getSuccessRate(0)) 


		print "====================SVM objects created=============================="		
	else:
		print "skipping writing of the service parameters into the json file"

	#create the PCA object for the unknown samples
	print "====================Creating PCA objects (unknown)=============================="		
	PCA_unknown = [None for x in range(0,max_levels)]
	for detail_coeff in level_steps:
		PCA_unknown[detail_coeff] = Flow_pca(unknown_flow_table, service_id, SUT, coeffs_idx=str(detail_coeff))
		print "normalizing unknown matrix for level %d, number of unknown matrices %d" % (detail_coeff, len(PCA_unknown))
		PCA_unknown[detail_coeff].normalize_and_scale()

		#make sure the number of features in the PCA_unknown matches the number of 
		#features PCA. to make this possible, we get the number of features in each
		#of the logisitic regression objects and get the number of features in these
		#objects
		PCA_features = PCA[detail_coeff].features

		print "before shape:",PCA_unknown[detail_coeff].X.shape," features:", PCA_features
		if (PCA_unknown[detail_coeff].X.shape[1] > (PCA_features)):
				PCA_unknown[detail_coeff].X = PCA_unknown[detail_coeff].X[:,:PCA_features]
		elif(PCA_unknown[detail_coeff].X.shape[1] < PCA_features):
			#add more columns
			ext_array = numpy.zeros([PCA_unknown[detail_coeff].X.shape[0],\
				PCA_features-PCA_unknown[detail_coeff].X.shape[1]], numpy.float)
			print "shape of extension array:",ext_array.shape
			PCA_unknown[detail_coeff].X = numpy.append(PCA_unknown[detail_coeff].X, ext_array, axis = 1) 
		print "after shape:",PCA_unknown[detail_coeff].X.shape


	print "====================PCA objects created (unknown)=============================="		
	

	print "====================Performing SVM on unknown flows ======================="
	#use the obj_LogReg to run a hypothesis test on each of the flow entry
	svm_unknown_data = [None]*(len(level_steps))
	predicted_labels = [None]*(len(level_steps))
	for detail_coeff in level_steps:
		svm_unknown_data[detail_coeff] = VectorDataSet(PCA_unknown[detail_coeff].X)
		svm_result = svm_classifier[detail_coeff].test(svm_unknown_data[detail_coeff])
		predicted_labels[detail_coeff] = svm_result.getPredictedLabels()
		print predicted_labels[detail_coeff]
	print "====================SVM performed (unknown)=============================="		

	print "===================Analyzing results ==================================="
	out_file = open('success_rate.log','a')	
	for detail_coeff in level_steps:
		predicted = 0.0
		unpredicted = 0.0
		out_str = "level:"+str(detail_coeff)+"\n"
		out_file.write(out_str)
		for i in range(0, len(predicted_labels[detail_coeff])):
			print "%s: %s" % (predicted_labels[detail_coeff][i], PCA_unknown[detail_coeff].Keys[i])
			if (predicted_labels[detail_coeff][i] == SUT):
				predicted+=1
			else:
				unpredicted+=1
		print "Success rate:%f, predicted:%f, unpredicted:%f" % (predicted/(predicted+unpredicted), predicted, unpredicted)	
		out_str = settings["apps"]["unknown"][0]+":"+str(predicted/(predicted+unpredicted))+"\n"
		out_file.write(out_str)

	out_file.close()


	
	te = time.time()

	print 'Total time taken = %f sec' % (te-ts)

#main function
if __name__=='__main__':
	print
	"===========================Initialization===================================="
	parser = OptionParser(usage="%prog [-l] <settings JSON>")
	parser.add_option("-l", "--learn", action="store_true", default=False, 
					dest="learn", help="Perform learning on the PCAp files or not")
	parser.add_option("-v", "--validation", action="store_true", default=False, 
					dest="validate", help="Perform validation on all the PCAP files")

	(parse_options, args) = parser.parse_args()	
	if len(args) != 1:
		parser.error("Incorrect number of arguments")
	print "Opening JSON file %s" %(args[0])
	json_data = open(args[0])
	service_id = {'netflix':1,'gmail':1, 'background':1}
	org_settings = json.load(json_data)
	SUT = "gmail"
	tmp_settings = org_settings
	print "The maximum number of levels required by the filter %d" % (org_settings["max_levels"])

	print "=====================Initialization done ============================"
	if (parse_options.validate == True):
		for apps_key in org_settings["apps"]:
			if (apps_key == "unknown"):
				continue
			print "Validating app:%s" % (apps_key)
			tmp_settings = org_settings
			SUT = apps_key
			start_idx = 0
			for app_idx in range(start_idx, len(org_settings["apps"][apps_key])):
				sample_app_test = tmp_settings["apps"][apps_key].pop(app_idx)
				#set the unknown sample to the sample_app_test
				print "Starting validation test with sample %s idx:%d" % (sample_app_test, app_idx)
				tmp_settings["apps"]["unknown"][0] = sample_app_test
				perform_classification(service_id=service_id, settings=tmp_settings, SUT=SUT,\
								options=parse_options)
				#insert the test sample back in its place
				tmp_settings["apps"][apps_key].insert(app_idx, sample_app_test)

	if (parse_options.validate == False):
		perform_classification(service_id=service_id, settings=tmp_settings, SUT=SUT,\
			options=parse_options)

			

		



