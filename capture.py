#!/usr/bin/python
# This is a simple capturer module to be used with IPolice6

import pdb

from scapy.all import *
import threading
import logging
import pcapy

logger = logging.getLogger("ipolice")

class SimpleCapturer(threading.Thread):
	''' The minimum requirements to be a working capturer'''
	run = 0
	captured = 0

	def run (self):
		'''Starts up a capturer'''
		logger.info("Capturer thread start")
		self.run = 1
		self.__capture()

	def stop (self):
		'''Attempts to cleanly shutdown the capturer, will block until it succeeds'''
		print "Attempting to shutdown capturer"
		self.run = 0
		self.join()
		print "Capturer thread terminated"

	def __init__(self, ipolice = None):
		'''Constructor takes an ipolice6 instance as single argument'''
		logger.debug("Init capture")
		self.parent = ipolice
		threading.Thread.__init__( self )
	
	def __submit(self, packet):
		''' Sticks packets into the queues of all the receivers'''
		if packet and self.parent:
			#packet = Ether(packet)
			#packet.show2()
			self.captured = self.captured + 1
			self.parent.submit_packet(packet)


	def __capture(self):
		''' Worker method called on run'''
		logger.info("Starting capture")
		
		cap = pcapy.open_live(self.dev, 1000, 1, 0)
		# Read packet  -- header contains information about the data from pcap,
		# payload is the actual packet as a string
		(header, payload) = cap.next()
		while header:
			#p = Ether(payload)
			#p.show2()
			packet = ''.join( [ "%02X " % ord( x ) for x in payload[12:14] ] ).strip()
			if packet == "86 DD": 
				#print packet
				self.__submit(payload)
			if not self.run:
				return
			(header, payload) = cap.next()


if __name__ == "__main__":
	pdb.set_trace()
	x = SimpleCapturer()
	x.dev = "eth0"
	x.run()
	print "bazinga"
