#!/usr/bin/python

import baseclasses

from scapy.all import *

class THCaction(baseclasses.IPolice6action):
	
	def execute(self, packet):
		print "This packet is deadbeef"
		print hexdump(packet)

