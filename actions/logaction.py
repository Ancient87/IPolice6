#!/usr/bin/python

import baseclasses
import logging
from scapy.all import *

class LogAction(baseclasses.IPolice6action):
	
	def __init__(self, message = "'%s triggered offending traffic (claims to) originate from %s' % (self.parent.name, packet.src)", parent = None):
		baseclasses.IPolice6action.__init__(self, name = "Logaction", parent=parent, description="meh")
		self.message = message
		self.logger = logging.getLogger("ipolice.logaction")
	
	def execute(self, packet):
		#print self.message
		import pdb
		try:
			self.logger.critical(eval(self.message))
		except NameError:
			self.logger.critical(self.message)
