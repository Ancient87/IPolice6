#!/usr/bin/python

import util
from util import *
from errors import *
import time
import datetime
from ipolice6 import logger

from conf import *
import pdb

class IPolice6Module():
	'''The standard IPolice6Module interface all modules must provide at least these method '''
	def __init__(self, name = "Generic Module", parent = None, main = None, description = "Base class for modules", ):
		self.description = description
		self.name = name
		self.parent = parent
		self.main = main
		self.interval = 5
		self.modules = []
		self.checks = []
		self.actions_fail = []
		self.actions_pass = []
		self.memory = {}
		self.callbacks = []
		self.interval = 5

	
	def __getitem__(self, key):
		'''Lets this work as a dictionary'''
		return self.memory[key]
	
	def __setitem__(self, key, value):
		'''Lets this work as a dictionary'''
		self.memory[key] = value
		return self.memory[key]

	def negative(self, packet):
		'''Called when the threat is not detected'''
		for action in self.actions_fail:
			action.execute(packet)
	def positive(self, packet):
		'''Called when checks suggest presence of threat'''
		#pdb.set_trace()
		for action in self.actions_pass:
			action.execute(packet)
			
	def register_check(self, check):
		'''Interface to add more checks to a module'''
		#TODO: CHeck valid
		if util.fulfills_interface(check, IPolice6check):
			self.checks.append(check)

	def register_pass(self, action):
		'''Interface to add action to be executed on positive result'''
		if has_function(action, "execute"):
			self.actions_pass.append(action)
		else: 
			raise NotAnActionError(action)

	def register_fail(self, action):
		'''Interface to add actions to be executed on negative result'''
		if hasFunction(action, "execute"):
			self.actions_fail.append(action)	
		else:
			raise NotAnActionError(action)

	def process_packet(self, packet):
		'''Main handler function, Passes the packet to each registered check until there is a verdict'''
		self.originalpacket = packet
		dissect = packet
		for check in self.checks:
			#print "Running check" + check.name
			import pdb
			#pdb.set_trace()
			result = check.check(packet)
			# Negative result
			if result is False:
				self.negative(packet)
				return False
			 # Result that immediately causes chain to succeed
			if result is True:
				self.positive(packet)
				return True
		# If we get here all tests passed
		self.positive(packet)
		return True
	
	def register_module(self, module, active = 0):
		'''Interface to add new modules to this module, will automatically detect id active or passive based using introspection'''
		if active:
			pass	
		else:
			if util.fulfills_interface(module, IPolice6Module):
	                        self.modules_passive.append(module)
				print (str(module) + "is passive")
			if util.fulfills_interface(module, IPolice6ModuleActive):
				print (str(module) + "is active")
				self.modules_active.append(module)

class IPolice6ModuleActive(IPolice6Module):
	'''Extension of the basic module which allows proactive probing'''
	def __init__(self, name = "Generic Active Module", parent = None, main = None, description = "Base class for modules", interval = 5):

		IPolice6Module.__init__(self, name, parent, main, description)
		self.delta = datetime.timedelta(seconds=interval)
		self.last = datetime.datetime.now() - self.delta #start immediately

	def istime(self):
		'''Function that establishes whether the module should be run based on the time passed since last execution'''
		if datetime.datetime.now() >= self.last + self.delta:
			self.last = datetime.datetime.now()
			return True
		else:
			return False
	
	def execute(self):
		'''Interface which is called by IPolice6 to run the probe'''
		if self.istime():
			self._do_execute()

	def _do_execute(self):
		'''This is where the code to be run goes'''
		pass

	def result(self, packet, res):
		if res:
			self.positive()
		else:
			self.negative()

class IPolice6check:
	'''Interface for an IPolice6check'''
	def __init__(self, name = "Base check", parent = None, description = "Simple check base class",action_fail = 2, action_pass = 0):
		self.parent = parent
		self.name = name
		self.description = description
		
		# Determines wether this check alone decides the result of the chain
		self.action_fail = action_fail
		# Determines wether this check alone decides the result of the chain
		self.action_pass = action_pass

	def check(self, packet):
		'''Needs to be overloaded by check writer, contains the code to be executed'''
		# Write your check code here
		pass

	def ret(self, bool):
		'''Utility function that determines what value to return based on the postive/negative behaviour of this check
		Functions should always return the result of this function rather than an absolute value'''
		if(bool):
			if self.action_pass == CONTINUE: #continue
				return CONTINUE
			if self.action_pass == IMMEDIATE_POSITIVE: #Immediate match
				return True
			elif self.action_pass == IMMEDIATE_NEGATIVE: #Immediate fail
				return False
		else:
			if self.action_fail == CONTINUE: #continue
				return CONTINUE
			if self.action_fail == IMMEDIATE_POSITIVE: #Immediate match
				return True
			elif self.action_fail == IMMEDIATE_NEGATIVE: #Immediate fail
				return False

	def __getitem__(self, key):
		'''Enabled dictionary like behaviour'''
		return self.parent.memory[key]
	
	def __setitem__(self, key, value):
		'''Enables dictionary like behaviour'''
		self.parent.memory[key] = value
		return self.parent.memory[key]



class IPolice6action:
	'''Interface for action'''
	def __init__(self, parent = None, name = "Base action", description = "Simple action base class"):
		self.parent = parent
		self.name = name
		self.description = description
	

	def execute(self, packet):
		'''Dummy method to be overloaded by action writer'''
		# Write your action code here
		pass
