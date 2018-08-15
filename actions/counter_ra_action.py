#!/usr/bin/python

import baseclasses

import util
from scapy.all import *
from ipolice6 import logger

class CounterRAaction(baseclasses.IPolice6action):
	
	def __init__(self, message = "Meh"):
		baseclasses.IPolice6action.__init__(self, name = "Logaction", parent=None, description="meh")
		self.message = message
	
	def execute(self, packet):
		if packet.haslayer(scapy.layers.inet6.ICMPv6NDOptPrefixInfo):
			packet.getlayer(scapy.layers.inet6.ICMPv6NDOptPrefixInfo).validlifetime=0x0 #change validlifetime to 0
			packet.getlayer(scapy.layers.inet6.ICMPv6ND_RA).routerlifetime = 0x0
			packet.getlayer(scapy.layers.inet6.ICMPv6ND_RA).cksum=None # force recalculation of chksum
			sink = util.StdOutDummy()
			sink.enable()
			sys.stdout = sink
			sendp(packet, verbose=0)
			sink.disable()
			logger.info("Sent counter RA")
