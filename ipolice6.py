#!/usr/bin/python

# This is the main class for the IPolice6 framework
import logging
import sys
import time
import pdb
# Set up import paths
sys.path.append('ip6modules')
sys.path.append('.')
sys.path.append('checks')
sys.path.append('actions')

# create logger
logger = logging.getLogger("ipolice")
logger.setLevel(logging.INFO)
# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.CRITICAL)
# create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to ch
ch.setFormatter(formatter)
# add ch to logger
logger.addHandler(ch)


#from baseclasses import *
#from ip6modules import *
#from actions import *
#from checks import *

import Queue
import threading
import util
import baseclasses
import capture
import time

from scapy.all import *


from conf import *
import configparser



# This is the main class for the Ipolice Framework

class IPolice6(threading.Thread):
	'''This is the main class for the Ipolice6 framework'''
	run = 1
	capturers = []
	loggers = []
	modules_passive = []
	modules_active = []
	packets = Queue.Queue(0)

	def __init__(self):
		'''Start thread'''
		threading.Thread.__init__(self)


	def __worker(self):
		'''Here we do all the work process the packet queue and run proactive tests'''
		while self.run:
			#print "Queue length: %d" % self.packets.qsize() 
			#Process a packet from the queue
			try:
				packet = self.packets.get(True,2)
				self.__process_packet(packet)
			except Queue.Empty:
				pass

			#Run all proactive tests
			for test in self.modules_active:
				test.execute()


	def register_capturer(self, capturer):
		'''API to add a capturer to the ipolice6'''
		#TODO: Check it's valid
		
		if util.fulfills_interface(capturer, capture.SimpleCapturer):
			self.capturers.append(capturer)
		else:
			raise NotACapturerException()


	def submit_packet(self, packet):
		'''Interface for capturers to add packets to the analysis queue'''
		#print "Submitting %s" % (packet)
		self.packets.put(packet)
		#print "Submitted"

	def __process_packet(self, packet):
		#Convert hex stream into Scappy Ethernet packet 
		if packet:
			packet = Ether(packet)
			#print "Processing"
			#packet.show2()
			#Pass packet to all modules
			for module in self.modules_passive:
				module.process_packet(packet)

	def run (self):
		'''Starts thread'''
		print "IPolice6 thread started"
		for capturer in self.capturers:
			capturer.start()
		self.__worker()
	
	def stop (self):
		'''Stops application'''
		# Kill capturer
		for capturer in self.capturers:
			capturer.stop()
			capturer.join()
		print "Attempting to shutdown main thread"
		self.run = 0
		self.join()
		print "Main thread done"
	
	def register_logger(self, logger):
		'''Registers loggers'''
		loggers.add(logger)

	def log(self, data):
		'''Invokes all the registered loggers log method'''
		for logger in loggers:
			logger.log(data)
	
	def register_module(self, module, active = 0):
		'''Interface to add new modules to this module, will automatically detect id active or passive based using introspection'''
		if active:
			pass	
		else:
			if util.fulfills_interface(module, baseclasses.IPolice6Module):
	                        self.modules_passive.append(module)
				print (str(module) + "is passive")
			if util.fulfills_interface(module, baseclasses.IPolice6ModuleActive):
				print (str(module) + "is active")
				self.modules_active.append(module)


def shutdown():
	print "Shutting down"
	ip.stop()
	ip.join()
	print "All threads done, closing main app"
	sys.exit(1)

			
if __name__ == "__main__":
	configfile = "configs/startup_config.conf"
	if len(sys.argv) > 1:
		configfile = sys.argv[1]

	parser = configparser.ConfigParser()
	conf = parser.parse_file(configfile)
	
	#pdb.set_trace()
	conf.start()

	try:
		while 1:
			time.sleep(10)	

	except KeyboardInterrupt:
		print "Shutting down"
		conf.stop()
		conf.join()
		print "All threads done, closing main app"
		sys.exit(1)
