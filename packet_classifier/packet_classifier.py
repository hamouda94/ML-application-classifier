#The code has been borrowed from pylibPCAp.sourceforge.net
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
from optparse import OptionParser
from net.ip.ip_packet import IP_packet
from net.tcp.tcp_packet import TCP_packet 
from flows.flow_table import Flow_table
from filters.pkt_filter import Pkt_filter
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
def process_pkt(pkt, known_flow_table, unknown_flow_table, pkt_filter):
	length= pkt[0]
	if (length == 0):
		print "found 0 length packet"
		return
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
		if (flow_entry == None):
			print "Could not create a flow entry"
			return
		if (flow_entry.pkts > 20):
			return
		#If the PCAP is the back-ground signature go ahead and update 
		#the flow entry blindly
		if ((pcap_file_key == "background") or \
				(flow_entry.service == "")):
			flow_entry.service = pcap_file_key

		if (flow_entry.pkts == 1):
			if pcap_file_key in supervised_samples:
				supervised_samples[pcap_file_key] += 1
			else:
				supervised_samples[pcap_file_key] = 1
		#apply the packet filter only for the first 1MB of traffic
		#We can change this to a certain number of packets.
		coeffs = pkt_filter.apply_filter(pkt_ip, flow_entry.flow_key)
		if (coeffs != None):
			for i in range(0, max_levels):
				if str(i) not in flow_entry.coeffs_dict:
					flow_entry.coeffs_dict[str(i)] = coeffs[i].tolist()
				else: 
					(flow_entry.coeffs_dict[str(i)]).extend(coeffs[i].tolist())
				if (len(flow_entry.coeffs_dict[str(i)]) > flow_table.max_coeffs[i]):
					flow_table.max_coeffs[i] = len(flow_entry.coeffs_dict[str(i)])

#main function
if __name__=='__main__':
	parser = OptionParser(usage="%prog [-l] <settings JSON>")
	parser.add_option("-l", "--learn", action="store_true", default=False, 
					dest="learn", help="Perform learning on the PCAp files or not")
	(options, args) = parser.parse_args()	
	if len(args) != 1:
		parser.error("Incorrect number of arguments")
	print "Opening JSON file %s" %(args[0])
	json_data = open(args[0])
	service_id = {'netflix':1,'gmail':1, 'background':1}
	settings = json.load(json_data)
	ts = time.time()
	print 'start time :%f' % ts
	max_levels = settings["max_levels"]  
	level_steps = settings["level_steps"]
	obj_LogReg = [{} for x in range(0, max_levels)]
	print "The maximum number of levels required by the filter %d" % (max_levels)
	SUT = "netflix"
	supervised_samples = {}
	PCA = [None for x in range(0, max_levels)]

	#session table, for known and unknown
	known_flow_table = Flow_table(max_levels)
	unknown_flow_table = Flow_table(max_levels)
	rt = time.time()
	pkt_filter = Pkt_filter("/home/asridharan/devsda5/filter_output.json",
						max_levels=max_levels)
	bkgnd_sess = 0


	#load the parameter file. the parameter file is expected to be a json file.
	#exit if the parameter file doesn't contain
	theta_params = {}
	if ("parameters" in settings["files"] and options.learn == False):
		for detail_coeff in level_steps:
			try:
				service_params_fd = open(settings["files"]["parameters"][detail_coeff], "r")
				service_params = json.load(service_params_fd) 
				print "creating logistic regression object  for level %d" % (detail_coeff)
				for service_key in service_params:
					theta_params = service_params[service_key]
					np_theta_params = numpy.array(theta_params)
					obj_LogReg[detail_coeff][service_key] = Flow_log_regg(None, None, None, \
						0.01, np_theta_params)
					print service_key," ",np_theta_params.shape
				service_params_fd.close()
			except IOError:
				print "unable to read service parameters json file:%s" % \
					(settings["files"]["parameters"][detail_coeff])

	if ("PCA" in settings["files"] and options.learn == False):
			for detail_coeff in level_steps:
				PCA[detail_coeff]= Flow_pca(json_store=settings["files"]["PCA"][detail_coeff])
			
			
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
			p = pcap.pcapObject()
			#open the dump file
			print "about to process signature for %s, from PCAp file %s" % \
				(pcap_file_key, settings["apps"][pcap_file_key][idx]) 
			p.open_offline(str(settings["apps"][pcap_file_key][idx]))
			pkt = p.next()
			while (pkt != None):
				#process the packet, generate coeffecients and update the flow 
				#table.
				process_pkt(pkt=pkt, known_flow_table = known_flow_table,\
					unknown_flow_table = unknown_flow_table, \
					pkt_filter=pkt_filter)
				pkt = p.next()

	#list the number of supervised samples
	for service in supervised_samples:
		print "supervised samples for %s:%d" % (service, supervised_samples[service])

	#initialize the PCA object
	if (options.learn == True):
		print "we need to learn/re-learn the theta parameters"
		for detail_coeff in level_steps:
			PCA[detail_coeff] = Flow_pca(known_flow_table, service_id, sut, str(detail_coeff))
			PCA[detail_coeff].normalize_and_scale()
			PCA[detail_coeff].performPCA()
			#get the reduced form of the matrix
			PCA[detail_coeff].store(settings["files"]["PCA"][detail_coeff])
			print "stored the u_reduce vector to persistent memory"


	#generate logistic reg parameters for each of the different services
	rewrite_param_json = False
	if (options.learn == True):
		for detail_coeff in level_steps:
			logistic_params = {}
			for service_key in settings["apps"]:
				#perform gradient descent for each of the applications 
				#specified except for the "unknown" service
				if (service_key == "unknown"):
					continue
				#do not create an logistic regression object if one already exists
				#we don't have service parameters for a particular service
				i = 0
				#generate decision vector
				Y = numpy.zeros([len(known_flow_table.flow_table), 1], numpy.float)
				for flow_key in known_flow_table.flow_table:
					if (known_flow_table.flow_table[flow_key].service == service_key):
						Y[i] = 1.0
					i += 1

				#create the logistic regression object for this service
				obj_LogReg[detail_coeff][service_key] = flow_log_regg(known_flow_table, PCA[detail_coeff].X, Y) 
				theta_params = obj_LogReg[detail_coeff][service_key].getparams()
				print theta_params
				logistic_params[service_key]=theta_params.tolist()
				print "created the logistic regression object for %s, coeff:%d" % (service_key, detail_coeff)
				#obtain hypothesis for each of the samples, to get an estimate of the 
				#average hypothesis
				print "avg hypothesis for service %s is: %f" % (service_key,\
				obj_LogReg[detail_coeff][service_key].hypothesisthres())

				#this is the file where the service parameters will be stored.
			print "writing the service parameters in the json file %s" %\
				(settings["files"]["parameters"][detail_coeff])
			param_fd = open(settings["files"]["parameters"][detail_coeff],"w")
			json.dump(logistic_params, param_fd)
			param_fd.close()
	else:
		print "skipping writing the of service parameters into the json file"

	#create the PCA object for the unknown samples
	print "creating the unknown sample matrix"
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

		#reduce the unknown matrix
		PCA_unknown[detail_coeff].X = PCA[detail_coeff].reduceVector(PCA_unknown[detail_coeff].X)
		print "reduced shape of unknown matrix is", PCA_unknown[detail_coeff].X.shape
	

	#use the obj_LogReg to run a hypothesis test on each of the flow entry
	i = 0
	cl_fd = open("classified.log","w")
	uncl_fd = open("unclassified.log", "w")
	for flow_key in unknown_flow_table.flow_table:
		flow_entry = unknown_flow_table.flow_table[flow_key]
		#check if the sessions already existed in the background session
		if flow_key in known_flow_table.flow_table:
			if (known_flow_table.flow_table[flow_key].service == "background"):
				flow_entry.service = known_flow_table.flow_table[flow_key].service
				continue
		server_key = str(flow_entry.server_ip) +"|"+str(flow_entry.server_port)
		for detail_coeff in level_steps:
			sample = numpy.array([PCA_unknown[detail_coeff].X[i,:]])
			#walk through the log-regressions objects for each of known apps and calcualte the hypothesis
			for service_key in settings["apps"]:
				if service_key == "unknown":
					continue
				flow_entry.hypothesis = obj_LogReg[detail_coeff][service_key].hypothesis(sample)
				if service_key in unknown_flow_table.services[server_key]:
					unknown_flow_table.services[server_key][service_key] +=\
					flow_entry.hypothesis
				else:
					unknown_flow_table.services[server_key][service_key] = flow_entry.hypothesis
		i += 1

	for server_key in unknown_flow_table.services:
		max_val = 0.0
		classified_service = ""
		print "Classifying server key:%s" % (server_key)
		for service_key in unknown_flow_table.services[server_key]:
			if unknown_flow_table.services[server_key][service_key] > max_val:
				max_val = unknown_flow_table.services[server_key][service_key]
				classified_service = service_key
		if (classified_service == SUT):
			cl_fd.write(server_key+":"+classified_service+":"+str(unknown_flow_table.services[server_key])+"\n")
		else:
			uncl_fd.write(server_key+":"+classified_service+":"+str(unknown_flow_table.services[server_key])+"\n")

	cl_fd.close()
	uncl_fd.close()
	te = time.time()

	print 'Total time taken = %f sec' % (te-ts)

		



