import os
import time
import numpy
from flows.flow_table import Flow_table

class Flow_pca:
	def __init__(self, flows):
		#Create the matrix X
		self.flows = flows
		self.X = numpy.zeros([flows.max_coeffs, len(flows.flow_table)],numpy.float)
		print "Creating X of shape:", self.X.shape
		#populate the array
		i = 0
		for keys in flows.flow_table.keys():
			j = 0
			if (len(flows.flow_table[keys].coeffs_dict)):
					for coeff in flows.flow_table[keys].coeffs_dict["0"]:
						self.X[j,i] = coeff
						j += 1
			i += 1

	def perform_pca(self):
		#Normalize the matrix X
		print "Calculating mean for the matrix X ...."
		ts = time.time()
		mu = numpy.std(self.X, axis = 1)
		te = time.time()
		print "Calculated the mean of the matrix ...."
		print "Time taken to calculate mean of the  matrix:%f seconds" % (te - ts)
		#Scale the matrix X
		print "Calculating the standard deviation of the matrix X ..."
		ts = time.time()
		s_std = numpy.std(self.X, axis = 1)
		te = time.time()
		print "Calculated the standard deviation matrix ...."
		print "Time taken to calculated standard deviation of the  matrix:%f seconds" % (te - ts)
		print "Scaling the matrix"
		ts = time.time()
		for i in range(0, self.X.shape[0]):
			for j in range(0, self.X.shape[1]):
				self.X[i,j] = (self.X[i,j] - mu[i])/s_std[i]
		te = time.time()
		print "Done scaling the matrix...."
		print "Time take to scale the matrix:%f seconds" % (te - ts)
		#Take the transpose of the matrix, since we want the columns to represent the features
		# and the rows to represent the dimensions
		#Generate the covariance matrix.
		print "Generating the covariance matrix ...."
		ts = time.time()
		cov_matrix = numpy.dot(self.X, self.X.T)
		cov_matrix = cov_matrix/self.X.shape[1]
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
		print "Required dimensions are %d" % (i)
		#Get the reduced U marix
		U_reduce = U[:,:i]
		print "Got new U_reduce with shape:",U_reduce.shape
		PCA = numpy.dot(U_reduce.T, self.X)
		print "Got the PCA with shape:", PCA.shape

		#update the dimension to which each entry belongs
		i = 0
		for keys in self.flows.flow_table.keys():
			self.flows.flow_table[keys].dimension = 0
			for j in range(0, PCA.shape[0]):
				if (PCA[j,i] > self.flows.flow_table[keys].dimension_val):
					self.flows.flow_table[keys].dimension = j
					self.flows.flow_table[keys].dimension_val = PCA[j,i]
			i += 1
		return
	

