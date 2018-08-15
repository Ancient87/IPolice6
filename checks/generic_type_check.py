#!/usr/bin/python

import baseclasses
from baseclasses import IPolice6check

from scapy.all import *
from ipolice6 import logger

class GenericTypeCheck(IPolice6check):
	
	def __init__(self, name = "Type check", parent = None, main = None, description = "Checks for dead beef", testType = None, nextlayer = True, decisive = False):
		IPolice6check.__init__(self, name, parent, description, nextlayer, decisive)
		self.testType = testType

	def check(self, packet, testType=None):
		#logger.debug(packet.show())
		testType = self.testType
		if isinstance(packet, self.testType):
			#logger.debug("BINGO!")
			return self.ret(packet, 1)
		else:
			#logger.debug("packet is of type "+str(type(packet))+" and we are looking for "+str(self.testType))
			return self.ret(packet, 0)
