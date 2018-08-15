#!/usr/bin/python

import baseclasses
from baseclasses import IPolice6check
from ipolice6 import logger
from scapy.all import *
import util

class CheckDosNewIp6(IPolice6check):
	'''Checks for presence of the DAD Spoof exploit'''
	def __init__(self, name = "DAD check", parent = None, main = None, description = "Checks for fish", action_fail = 2, action_pass = 1):
		IPolice6check.__init__(self, name=name, parent=parent, description=description, action_fail = action_fail, action_pass = action_pass)

	
	def check(self, packet):
		import pdb
		if self['reset']:
			return self.ret(False)
		if packet.haslayer(scapy.layers.inet6.ICMPv6ND_NA):

			packet = packet.getlayer(scapy.layers.inet6.ICMPv6ND_NA)
			#pdb.set_trace()
		else:
			return False
		#logger.debug("%s baits remaining" % (str(self.parent['bait'])))
		#pdb.set_trace()
		for bait in self.parent['bait']:
			baittemp = util.get_ip6_padded(bait)
			target = util.get_ip6_padded(packet.tgt)
			#print "The target %s , what we want %s" % (target, bait)
			if target == baittemp:
				self.parent['bait'].remove(bait)
				#print self['bait']
				#logger.debug("Removed bait bait  %s reamining %d" % (bait, len(self.parent['bait'])))
		if len(self.parent['bait']) <= 0:
			#pdb.set_trace()
			self.parent.memory['reset'] = True
			self['active'] = True
			return self.ret(True)
		return self.ret(False)


class CheckParasite6(IPolice6check):
	'''Check for the presence of MITM attack by checking a given MAC can not own more than x (defualt 4) IPs'''
	def __init__(self, name = "CheckParasite6", parent = None, main = None, description = "Checks how many ip's are associated with a given MAC Address", action_fail = 2, action_pass = 1):
		IPolice6check.__init__(self, name, parent, description, action_fail, action_pass)


	def check(self, packet):
		'''Checks the list'''
		import pdb

	
		#Get Target
		if packet.haslayer(scapy.layers.inet6.ICMPv6ND_NA):
			layer = packet.getlayer(scapy.layers.inet6.ICMPv6ND_NA)
		else:
			return False


		target = layer.tgt

		if packet.haslayer(scapy.layers.inet6.ICMPv6NDOptDstLLAddr):
			#pdb.set_trace()
			layer = packet.getlayer(scapy.layers.inet6.ICMPv6NDOptDstLLAddr)
		else:
			return False

		#Get entry for this MAC
		mac = layer.lladdr
		try:
			list = self['ndp_cache'][mac]

		except KeyError:
			self['ndp_cache'][mac] = []
			list = self['ndp_cache'][mac]
		try:
			router = self['router_mac_ip']
			if target == router[1]:
				if not mac == router[0]:
					#Someone is attempting to impersonate router
					self['ndp_cache'] = {}
					return self.ret(True)
		except KeyError:
			pass

		if not target in list:
			list.append(target)

		if len(list) > self['ips']:
			list = []
			self['ndp_cache'] = {}
			return self.ret(True)
	
		return self.ret(False)

class CheckRedir6(IPolice6check):
	'''Checks for the presence of redirect6 exploit by tracing the flow of ping requests and corresponding redirects'''
	def __init__(self, name = "CheckRedir6", parent = None, main = None, description = "Check for suspicious patterns of Echo Requests Responses followed by Redirect/Resize containing the response", action_fail = 2, action_pass = 1, layer = None):
		IPolice6check.__init__(self, name, parent, description, action_fail, action_pass)
		self.layer = layer

	def check(self, packet):
		# Echo Response ?
		if packet.haslayer(scapy.layers.inet6.ICMPv6EchoReply):
			layer = packet.getlayer(scapy.layers.inet6.ICMPv6EchoReply)
			#get data
			self['responses'].append(layer.data)
			return False
		elif packet.haslayer(self.layer):
			layer = packet.getlayer(self.layer)
			import pdb
			#pdb.set_trace()
			# go find data pattern
			packet_text = layer.build()
			import re
			for data in self['responses']:
				exp = re.compile(data)
				res = exp.search(data)
				if not res is None:
					return self.ret(True)
			return self.ret(False)
		else:
			return False
