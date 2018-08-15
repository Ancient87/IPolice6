#!/usr/bin/python

import baseclasses

import util
from scapy.all import *
from logging.handlers import SysLogHandler
import logging
import syslog
import sys

class SysLogAction(baseclasses.IPolice6action):
	'''Simple action that implements logging to a syslog sever'''
	def __init__(self, message = "'%s triggered offending packet: %s' % (self.parent.name, self.dump(packet))", server="localhost", port=514, facility=SysLogHandler.LOG_LOCAL1, severity="INFO"):
		baseclasses.IPolice6action.__init__(self, name = "Logaction", parent=None, description="Simple syslogger")
		self.message = message
		self.logger = logging.getLogger()
		self.logger.setLevel(logging.INFO)
		syslog = SysLogHandler((server, port), facility)
	
	def dump(self, packet):
		''' Helper Method that returns a detailed information on the packet being dumped'''
		tmp = ""
		x = util.StdOutDummy(tmp)
		sys.stdout = x
		packet.show(indent=0)
		sys.stdout = sys.__stdout__
		ret = x.loc
		import re
		ret = re.sub("  +", " ", ret)
		return ret


	def execute(self, packet):
		''' Overriden from Action interface, attempts to eval message and log it'''
		try:
			syslog.openlog("ipolice6", 0, syslog.LOG_LOCAL1)
			import pdb
			syslog.syslog(eval(self.message))
			#self.logger.info(eval(self.message))
		except NameError:
			syslog.openlog("ipolice6", 0, syslog.LOG_LOCAL1)
			syslog.syslog(self.message)
			#self.logger.info(self.message)
