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
	logistic_params = {}
	obj_LogReg = {}
	service_id = {'netflix':1,'gmail':1, 'background':1}
	settings = json.load(json_data)
	ts = time.time()
	print 'start time :%f' % ts
	detail_coeff = "21"
	SUT = "netflix"
	supervised_samples = {}

	#session table, for known and unknown
	known_flow_table = Flow_table()
	unknown_flow_table = Flow_table()
	rt = time.time()
	pkt_filter = Pkt_filter("/home/asridharan/devsda5/Filter_output.json")
	bkgnd_sess = 0


	#Load the parameter file. The parameter file is expected to be a JSON file.
	#Exit if the parameter file doesn't contain
	theta_params = {}
	if ("parameters" in settings["files"]):
		try:
			service_params_fd = open(settings["files"]["parameters"], "r")
			service_params = json.load(service_params_fd) 
			for service_key in service_params.keys():
				theta_params = service_params[service_key]
				np_theta_params = numpy.array(theta_params)
				obj_LogReg[service_key] = Flow_log_regg(None, None, None, \
					0.01, np_theta_params)
				print service_key," ",np_theta_params.shape
		except IOError:
			print "Unable to read service parameters JSON file:%s" % \
				(settings["files"]["parameters"])

	if ("PCA" in settings["files"]):
			PCA = Flow_pca(json_store=settings["files"]["PCA"])
			
			
	#PCAP file processing....
	for pcap_file_key in settings["apps"].keys():
		#If we already have a pcap file, continue
		if (pcap_file_key in obj_LogReg.keys()):
			print "Already have parameters for service %s, not reading PCAP file" \
					% (pcap_file_key)
			continue
		#Create the pcap object
		for idx in range(0,len(settings["apps"][pcap_file_key])):
			p = pcap.pcapObject()
			#Open the dump file
			print "About to process signature for %s, from PCAP file %s" % \
				(pcap_file_key, settings["apps"][pcap_file_key][idx]) 
			p.open_offline(str(settings["apps"][pcap_file_key][idx]))
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
					if (flow_entry == None):
						#Unsupported flow
						pkt = p.next()
						continue
					if (flow_entry.pkts > 20):
						#Don't process any more packets for this flow.
						pkt = p.next()
						continue
					#If the PCAP is the back-ground signature go ahead and update 
					#the flow entry blindly
					if ((pcap_file_key == "background") or \
						(flow_entry.service == "")):
						flow_entry.service = pcap_file_key
						if (flow_entry.pkts == 1 and pcap_file_key == "background"):
							bkgnd_sess += 1

					if (flow_entry.pkts == 1):
						if pcap_file_key in supervised_samples.keys():
							supervised_samples[pcap_file_key] += 1
						else:
							supervised_samples[pcap_file_key] = 1
					#apply the packet filter only for the first 1MB of traffic
					#We can change this to a certain number of packets.
					coeffs = pkt_filter.apply_filter(pkt_ip, flow_entry.flow_key)
					if (coeffs != None):
						for i in range(0,22):
							if (str(i) not in flow_entry.coeffs_dict.keys()):
								flow_entry.coeffs_dict[str(i)] = coeffs[i].tolist()
							else: 
								(flow_entry.coeffs_dict[str(i)]).extend(coeffs[i].tolist())
						if (len(flow_entry.coeffs_dict[detail_coeff]) > flow_table.max_coeffs):
							flow_table.max_coeffs = len(flow_entry.coeffs_dict[detail_coeff])
				pkt = p.next()

	#List the number of supervised samples
	for service in supervised_samples.keys():
		print "Supervised samples for %s:%d" % (service, supervised_samples[service])

	#Initialize the PCA object
	if (len(known_flow_table.flow_table) > 0):
		print "We have flows in the known PCAP, hence need to perform learning"
		PCA = Flow_pca(known_flow_table, service_id, SUT, detail_coeff)
		PCA.normalize_and_scale()
		PCA.performPCA()
		#Get the reduced form of the matrix
		PCA.store(settings["files"]["PCA"])
		print "Stored the U_reduce vector to persistent memory"


	#Generate logistic reg parameters for each of the different services
	avg_unknown_hypothesis = {}
	classified_flows = {}
	rewrite_param_json = False
	for service_key in settings["apps"].keys():
		avg_unknown_hypothesis[service_key] = 0.0
		classified_flows[service_key] = 0
		#Do not create an logistic regression object if one already exists
		if (service_key in obj_LogReg.keys()):
			print "Not creating a logistic regression object for service %s.."\
				%(service_key)
			continue
		#Perform gradient descent for each of the applications specified, 
		#except for the "unknown" service
		if (service_key == "unknown"):
			continue
		#We don't have service parameters for a particular service
		rewrite_param_json = True
		i = 0
		#Generate decision vector
		Y = numpy.zeros([len(known_flow_table.flow_table), 1], numpy.float)
		for flow_key in known_flow_table.flow_table.keys():
			if (known_flow_table.flow_table[flow_key].service == service_key):
				Y[i] = 1.0
			i += 1

		#Create the logistic regression object for this service
		obj_LogReg[service_key] = Flow_log_regg(known_flow_table, PCA.X, Y) 
		theta_params = obj_LogReg[service_key].getParams()
		logistic_params[service_key]=theta_params.tolist()
		print "Created the logistic regression object for %s" % (service_key)
		#Obtain hypothesis for each of the samples, to get an estimate of the 
		#average hypothesis
		print "Avg hypothesis for service %s is: %f" % (service_key,\
			obj_LogReg[service_key].hypothesisThres())

	#Store the logistic regression parameters for later use.
	if (rewrite_param_json == True):
		#This is the file where the service parameters will be stored.
		print "Writing the service parameters in the JSON file"
		param_fd = open("service_params.json","w")
		json.dump(logistic_params, param_fd)
	else:
		print "Skipping writing the service parameters intO the JSON file"

	#Create the PCA object for the unknown samples
	print "Creating the unknown sample matrix"
	PCA_unknown = Flow_pca(unknown_flow_table, service_id, SUT, detail_coeff)
	PCA_unknown.normalize_and_scale()

	#Make sure the number of features in the PCA_unknown matches the number of 
	#features PCA. To make this possible, we get the number of features in each
	#of the logisitic regression objects and get the number of features in these
	#objects
	PCA_features = PCA.features

	print "before shape:",PCA_unknown.X.shape," features:", PCA_features
	if (PCA_unknown.X.shape[1] > (PCA_features)):
			PCA_unknown.X = PCA_unknown.X[:,:PCA_features]
	elif(PCA_unknown.X.shape[1] < PCA_features):
		#add more columns
		ext_array = numpy.ones([PCA_unknown.X.shape[0],\
			PCA_features-PCA_unknown.X.shape[1]], numpy.float)
		print "Shape of extension array:",ext_array.shape
		PCA_unknown.X = numpy.append(PCA_unknown.X, ext_array, axis = 1) 
	print "after shape:",PCA_unknown.X.shape

	#Reduce the unknown matrix
	PCA_unknown.X = PCA.reduceVector(PCA_unknown.X)
	print "Reduced shape of unknown matrix is", PCA_unknown.X.shape
	

	#Use the obj_LogReg to run a hypothesis test on each of the flow entry
	i = 0
	error = 0
	false_neg = 0
	classified_samples = 0
	unknown_samples = 0
	unknown_bkgnd_sess = 0
	cl_fd = open("classified.log","w")
	uncl_fd = open("unclassified.log", "w")
	for flow_key in unknown_flow_table.flow_table.keys():
		flow_entry = unknown_flow_table.flow_table[flow_key]
		Sample = numpy.array([PCA_unknown.X[i,:]])
		max_hypothesis = 0.0
		#Check if the sessions already existed in the background session
		if flow_key in known_flow_table.flow_table.keys():
			if (known_flow_table.flow_table[flow_key].service == "background"):
				flow_entry.service = known_flow_table.flow_table[flow_key].service
				unknown_bkgnd_sess += 1
				continue
		if (flow_entry.service == "unknown"):
			unknown_samples += 1
		#Walk through the log-regressions objects for each of known apps and calcualte the hypothesis
		for service_key in settings["apps"].keys():
			if service_key == "unknown":
				continue
			flow_entry.hypothesis = obj_LogReg[service_key].hypothesis(Sample)
			if (flow_entry.hypothesis > max_hypothesis):
				max_hypothesis = flow_entry.hypothesis
				flow_entry.service = service_key
			avg_unknown_hypothesis[service_key] += flow_entry.hypothesis
		flow_entry.hypothesis = max_hypothesis
		if (flow_entry.service in classified_flows.keys()):
			classified_flows[flow_entry.service] += 1
		else:
			classified_flows[flow_entry.service] = 1
		 #Keep track of how many flows are classified as the cassified_service
		if (flow_entry.service == SUT):
			classified_samples += 1
			flow_entry.print_entry(cl_fd)
		else:
			flow_entry.print_entry(uncl_fd)
		#increment the counter in the matrix
		i += 1

	cl_fd.close()
	uncl_fd.close()

	for service_key in settings["apps"].keys():
		if service_key == "unknown":
			continue
		avg_unknown_hypothesis[service_key] = avg_unknown_hypothesis[service_key]/unknown_samples
		print "Average unkown hypothesis/flows(%s):%f/%d" % (service_key, avg_unknown_hypothesis[service_key], classified_flows[service_key])
	te = time.time()
	print "unknown samples:%d, background:%d classified samples:%d, unkwn bkgnd sess:%d, false_neg:%d" % \
		(unknown_samples, bkgnd_sess, classified_samples, unknown_bkgnd_sess, false_neg)
	print 'Total time taken = %f sec' % (te-ts)

		



