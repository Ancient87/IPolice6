#!/usr/bin/python

import baseclasses
from baseclasses import IPolice6check

from scapy.all import *

class GenericFieldCheck(IPolice6check):
	'''Bread and butter generic check which provides all functionality needed for a classic static packet filter'''
	def __init__(self, name = "Type check", parent = None, main = None, description = "Generic type check that checks if a packet has a layer/type/field", testField=None, testValue=None, testValues = [], action_pass = 0, action_fail = 2, layer = None):
		IPolice6check.__init__(self, name, parent, description, action_fail, action_pass)
		self.field = testField
		self.testValues = testValues
		self.value = testValue
		self.layer = layer

	def check(self, packet):
		'''Checks for presence of (list of) values in specified field in packet, success if found fail if not'''
		import pdb
		if self.layer is None: #Useless
			self.ret(False)
		#pdb.set_trace()
		if packet.haslayer(self.layer):
			layer = packet.getlayer(self.layer)
			if self.layer == scapy.layers.inet6.ICMPv6NDOptPrefixInfo:
				pass
			if not self.field is None:
				try:
					tmp = "layer.%s" % (self.field)
					#print tmp
					#print eval(tmp)
					tmp = eval(tmp)

					if self.value:
						self.testValues.append(self.value)
						self.value = None

					res = False
					for val in self.testValues:
						if self.name is "Check prefix valid":
							pass
							#print "what we got %s , what we want %s" %(tmp,val)
						if tmp == val:
							#print "tmp:%s = val:%s" % (tmp, val)
							res = True

					return self.ret(res)
				except AttributeError:
					return self.ret(False)
			else:
				self.ret(True)
		else:
			return False
