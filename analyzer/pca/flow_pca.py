import os
import time
import numpy
import json
from flows.flow_table import Flow_table

class Flow_pca:
	def store(self, store_file):
		pca_store = {}
		U_reduce_list = self.U_reduce.tolist()
		u_reduce_fd = open(store_file,"w")
		pca_store["features"] = self.features
		pca_store["U_reduce"] = U_reduce_list
		json.dump(pca_store, u_reduce_fd)
		u_reduce_fd.close()

	def loadPCAFromStore(self, json_store):
		try:
			PCA_fd = open(json_store, "r")
			PCA_json = json.load(PCA_fd)
			self.features = PCA_json["features"]
			U_reduce_list = PCA_json["U_reduce"]
			self.U_reduce = numpy.array(U_reduce_list)
		except IOError:
			print "Unable to open %s" % (json_store)
			return False
		return True
			
	def __init__(self, flows = None, service_id = None, SUT="", coeffs_idx = "0", json_store = None):
		#Create the matrix X
		#Rows are samples (sessions), and columns are features (coefficients)
		if json_store != None:
			if (self.loadPCAFromStore(json_store) == True):
				return 
			else:
				return None
		self.flows = flows
		print "Using coefficient %d for analysis.." % (int(coeffs_idx))
		#Add an extra column to set the service ID
		self.X = numpy.zeros([len(flows.flow_table), flows.max_coeffs[int(coeffs_idx)]],numpy.float)
		self.dimensions = 0
		self.features = self.X.shape[1]
		self.L = ["" for x in range(0,self.X.shape[0])]
		self.Keys = ["" for x in range(0,self.X.shape[0])]
		print "Creating X of shape:", self.X.shape
		#populate the array
		i = 0
		for keys in flows.flow_table:
			j = 0
			if (len(flows.flow_table[keys].coeffs_dict)):
					if (flows.flow_table[keys].service == SUT):
						self.L[i] = flows.flow_table[keys].service
					else:
						self.L[i] = "Other"
					self.Keys[i] = keys
					for coeff in flows.flow_table[keys].coeffs_dict[coeffs_idx]:
						self.X[i,j] = coeff
						j += 1
			i += 1
	def normalize_and_scale(self):
		#Normalize the matrix X
		print "Calculating mean for the matrix X ...."
		ts = time.time()
		mu = numpy.mean(self.X, axis = 0)
		te = time.time()
		print "Calculated the mean of the matrix ...."
		print "Time taken to calculate mean of the  matrix:%f seconds" % (te - ts)
		#Scale the matrix X
		print "Calculating the standard deviation of the matrix X ..."
		ts = time.time()
		s_std = numpy.std(self.X, axis = 0)
		te = time.time()
		print "Calculated the standard deviation matrix ...."
		print "Time taken to calculated standard deviation of the  matrix:%f seconds" % (te - ts)
		print "Scaling the matrix"
		ts = time.time()
		for i in range(0, self.X.shape[0]):
				for j in range(0, self.X.shape[1]):
					if (s_std[j] != 0) :
						self.X[i,j] = (self.X[i,j] - mu[j])/s_std[j]
		te = time.time()
		print "Done scaling the matrix...."
		print "Time take to scale the matrix:%f seconds" % (te - ts)

	def performPCA(self):
		#Take the transpose of the matrix, since we want the columns to represent the features
		# and the rows to represent the dimensions
		#Generate the covariance matrix.
		print "Generating the covariance matrix ...."
		ts = time.time()
		cov_matrix = numpy.dot(self.X.T, self.X)/(self.X.shape[1])
		te = time.time()
		print "Finished generating the covariance matrix"
		print "Time taken to calcualte COV:%f seconds" % (te - ts)
		#perform SVD on the SIGMA matrix
		print "Calculating SVD of cov_matrix"
		ts = time.time()
		[U,S,V] = numpy.linalg.svd(cov_matrix)
		te = time.time()
		print "Finished calculating SVD, U:",U.shape,"S:",S.shape,"V:",V.shape
		print "Time taken to calculate SVD:%f seconds" % (te - ts)
		#Analyze the S matrix to understand the number of dimensions to which 
		print "Calculating required dimensions"
		S_sum  = 0
		S_parsum = 0
		for i in range(0, S.shape[0]):
			S_sum += S[i]
		for i in range (0, S.shape[0]):
			S_parsum += S[i]
			if (S_sum == 0):
				print"ERROR:S_sum is zero. Will result in divide by zero error!!"
			if ( (1 -  S_parsum/S_sum ) < 0.01 ) :
				break
		self.dimensions = i
		print "Required dimensions are %d" % (self.dimensions)
		self.dim_service_list = [{} for k in range(self.dimensions)]

		#Get the reduced U marix
		self.U_reduce = U[:,:self.dimensions]
		print "Got new U_reduce with shape:",self.U_reduce.shape
		self.X = numpy.dot(self.X, self.U_reduce)
		print "Got the PCA with shape:", self.X.shape

		return

	def reduceVector(self, X):
		#X is an MxN matrix and self.U_reduce is an NxK matrix
		return numpy.dot(X, self.U_reduce)

	def getUReduce(self):
		return self.U_reduce


	

