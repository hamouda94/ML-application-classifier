import os
import time
import numpy
from flows.flow_table import Flow_table

class Flow_pca:
	def __init__(self, flows, coeffs_idx = "0"):
		#Create the matrix X
		#Rows are samples (sessions), and columns are features (coefficients)
		self.flows = flows
		print "Using coefficient %s for analysis.." % (coeffs_idx)
		self.X = numpy.zeros([len(flows.flow_table), flows.max_coeffs],numpy.float)
		self.dimensions = 0
		print "Creating X of shape:", self.X.shape
		#populate the array
		i = 0
		for keys in flows.flow_table.keys():
			j = 0
			if (len(flows.flow_table[keys].coeffs_dict)):
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

	def perform_pca(self):
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
		for i in range (0, self.X.shape[0]):
			S_parsum += S[i]
			if ( (1 -  S_parsum/S_sum ) < 0.01 ) :
				break
		self.dimensions = i
		print "Required dimensions are %d" % (self.dimensions)
		self.dim_service_list = [{} for k in range(self.dimensions)]

		#Get the reduced U marix
		self.U_reduce = U[:,:self.dimensions]
		print "Got new U_reduce with shape:",self.U_reduce.shape
		PCA = numpy.dot(self.X, self.U_reduce)
		print "Got the PCA with shape:", PCA.shape

		#update the dimension to which each entry belongs
		i = 0
		for flow_key in self.flows.flow_table.keys():
			self.flows.flow_table[flow_key].dimension = 0
			mean_vec = PCA[i,:]
			flow_sum = numpy.sum(mean_vec)
			flow_entry = self.flows.flow_table[flow_key]
			flow_entry.dimenion_val = 0
			max_per = 0
			for j in range(0, PCA.shape[1]):
				if ((PCA[i,j]/flow_sum )> max_per):	
					max_per = PCA[i,j]/flow_sum
					flow_entry.dimension = j
					flow_entry.dimension_val = max_per

			if flow_entry.service in self.dim_service_list[flow_entry.dimension].keys():
				self.dim_service_list[flow_entry.dimension][flow_entry.service] += flow_entry.dimension_val
			else:
				self.dim_service_list[flow_entry.dimension][flow_entry.service] = flow_entry.dimension_val
			i += 1
		common_dim = {}
		print "Generating dimension service list....."
		for i in range(0, self.dimensions):
			if ("unkown" in self.dim_service_list[i].keys()):
				for service in self.dim_service_list[i].keys(): 
					 if (service == "unkown"):
					 	continue
					 if service not in common_dim.keys():
					 	common_dim[service] = self.dim_service_list[i]["unkown"]
					 else:
					 	common_dim[service] += self.dim_service_list[i]["unkown"]
		print "Final list of similarity score:"
		for service in common_dim.keys():
			if service == "unkown":
				continue
			print "%s: %f" % (service, common_dim[service])
		return


	

