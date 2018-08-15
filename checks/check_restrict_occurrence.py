#!/usr/bin/python

import baseclasses
from baseclasses import IPolice6check
from ipolice6 import logger
from scapy.all import *
import util


class CheckRestrictOccurrence(IPolice6check):
	
	def __init__(self, name = "Restrict occurrence check", parent = None, main = None, description = "Checks if a given layer exists more than x times", action_fail = 2, action_pass = 1):
		IPolice6check.__init__(self, name, parent, description, action_fail = action_fail, action_pass = action_pass)

	
	def check(self, packet):
		import pdb
		counter = 0
		layer = packet
		while layer.haslayer(self.layer):
			#pdb.set_trace()
			layer = layer.getlayer(self.layer)
			layer = layer.payload
			counter = counter + 1
		
		if counter >= self.max_occurrence:
			return self.ret(True)

		return self.ret(False)
