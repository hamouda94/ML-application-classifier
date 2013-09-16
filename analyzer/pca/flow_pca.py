import os
import numpy
from flows.flow_table import Flow_table

class Flow_pca:
	def __init__(self, flows):
		#Create the matrix X
		self.X = numpy.zeros([len(flows.flow_table), flows.max_coeffs],numpy.float)
		print "Creating X of shape:", self.X.shape
		#populate the array
		i = 0
		for keys in flows.flow_table.keys():
			j = 0
			if (len(flows.flow_table[keys].coeffs_dict)):
					for coeff in flows.flow_table[keys].coeffs_dict["0"]:
						self.X[i,j] = coeff
						j += 1
			i += 1

	def perform_pca(self):
		#Normalize the matrix X
		print "Starting normalization of the matrix X ...."
		mu = []
		for i in range(0, self.X.shape[0]):
			mu.insert(i,0)
			for j in range(0, self.X.shape[1]):
				mu[i] += self.X[i,j]
			mu[i] = mu[i]/self.X.shape[1]
			for j in range(0, self.X.shape[1]):
				self.X[i,j] -= mu[i]
		print "Normalized the matrix ...."
		#Scale the matrix X
		print "Starting to scale the matrix X ..."
		s_max = []
		for i in range(0, self.X.shape[1]):
			s_max.insert(i, self.X[i].max())
			if (s_max[i] == 0):
				continue
			for j in range (0, self.X.shape[1]):
				self.X[i,j] = (self.X[i,j] - mu[i])/s_max[i]
		print "Scaled the matrix ...."
		#Generate the covariance matrix.
		print "Generating the covariance matrix ...."
		cov_matrix = numpy.zeros([self.X.shape[0], self.X.shape[0]], numpy.float) 
		for j in range(0, self.X.shape[1]):
			x_i = numpy.array([self.X[:,j]])
			cov_matrix = numpy.add(cov_matrix , numpy.dot(x_i.T, x_i))
		print "Finished generating the covariance matrix"
			
		#perform SVD on the SIGMA matrix
		#Analyze the S matrix to understand the number of dimensions to which 
		#the matrix X can be reduced. 
		#Take the first k columns of U, these are the k eigen vectors we are looking 
		#for.
		#
		return
	

