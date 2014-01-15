ML-application-classifier
==================
The ML-application-classifier is a python tool that uses support vector machines to
classify services running on a particular server. The input to the tool is a set of PCAP
files. The tool organizes the packets within the PCAP files into "service
samples". A service is defined as a combination of an IP address, a protocol
(TCP/UDP) and a port. A service sample consists of the service (IP address + protocol +
port) as a key, and the lengths of all packet, in both directions( client -> server
and server -> client)  as the data. Since, support vector machines is a
supervised learning algorithm, the PCAP files fed into the tool need to have a
set of known service samples that will help the tool learn the classification
parameters. Once the tool has learnt the classification parameters, new PCAP
files can be fed into the tool to classify the unkown service samples into
services that the tool has already learnt using the supervised samples.

Python module Dependcies
=========================
The tool is dependent on the following python modules:
* dpkt : This module is used to read the packets from the PCAP files, and parse
  the IP headers to organize the packets into service samples.
* PyML : This is the support vector machine implementation used by the tool to
  run the supervised algorithm to perform application classification.

Usage
======
The main python script is packet_classifier/packet_classifier_svm.py. You can
run the tool using the following command:

	python packet_classifier_svm.py --learn settings.json

The settings.json file has all the input parameters in JSON format, and should
be self explanatory.



