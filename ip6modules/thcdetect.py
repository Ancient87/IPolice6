#!/usr/bin/python

import time
import datetime
from scapy.all import *
import pdb

from ipolice6 import logger
import util
import baseclasses
from baseclasses import IPolice6ModuleActive
import checks.thc_checks
import checks.generic_field_check
import actions.logaction


class DetectDosNewIp6(IPolice6ModuleActive):
	'''This module detects the dos-new-ip attack from the thc toolkit by sending out randomly generated NS requests which should not be answered by anyone but the attacker'''
	def __init__(self, name = "DetectDoSNewIp6", parent = None, main = None, description = "Active DaD spoof module", amount = 4):
		IPolice6ModuleActive.__init__(self, name = name, parent = parent, main = main, description = description)
		self['reset'] = 1
		self.register_check(checks.thc_checks.CheckDosNewIp6(parent = self, action_pass = 1, action_fail = 2))
		self.register_pass(actions.logaction.LogAction(message = "'Bait swallowed - DAD DOS very likely'"))
		self.amount = amount
		self['bait'] = []
		#pdb.set_trace()

	def sendbait(self):
		for ip in self['bait']:
			#Create ICMPv6 ND NS
			#print ip
			ns = ICMPv6ND_NS(tgt=ip)

			#Create L3 packet
			tmp = util.get_ip6_solicitated_multicast(ip)
			#print tmp
			packet = IPv6(src = "::", dst = util.get_ip6_solicitated_multicast(ip))

			#Create L2 datagram
			dg = Ether(dst=util.get_ethernet_solicitated_multicast(ip))/packet/ns
			sink = util.StdOutDummy()
			sink.enable()
			sendp(dg, verbose=0)
			sink.disable()

	def _do_execute(self):
		# only do this if we need to reset
		if self['reset']:
			# make new pakets
			for i in range (1, self.amount):
				ip = util.get_random_ip6_address()
				self['bait'].append(ip)
			# acknowledge the reset
			self['reset'] = False
		self.sendbait()

class DetectParasite6(IPolice6ModuleActive):
	'''This module detects the parasite6 MITM attack from the thc toolkit by attempting to limit the amount of IPs a MAC address may claim to have at one time'''

	def __init__(self, name = "DetectParasite6", parent = None, main = None, description = "Detects NDP spoof MITM attacks as done by parasite6", ips = 2, reset_interval = 21600, router_mac_ip = ()):
		IPolice6ModuleActive.__init__(self, name = name, parent = parent, main = main, description = description, interval = reset_interval)
		self['ips'] = ips
		self[router_mac_ip] = router_mac_ip
		self['ndp_cache'] = {} # initialise cache

		#Setup checks
		self.register_check(checks.thc_checks.CheckParasite6(parent = self))

		#Setup action
		self.register_pass(actions.logaction.LogAction(message = "'A machine on the network is claiming to have more than %d ips' % (self.parent['ips'])", parent = self))

	
	def _do_execute(self):
		self['ndp_cache'] = {} # clear cache on timeout

class DetectRedir6(IPolice6ModuleActive):
	'''This module detects the redir6 ICMPv6 Router redirect attack from the thc toolkit by tracking all the ICMP Echo responses flowing through the network as well as the Redirects and flags Redirected Responses as suspicious'''

	def __init__(self, name = "DetectRedirect6", parent= None, main = None, description = "Detects potential malicious uses of ICMPv6 Router Redirects as performed by redir6", reset_interval = 3000, mtu = False, allowed = True):
		IPolice6ModuleActive.__init__(self, name = name, parent = parent, main = main, description = description, interval = reset_interval)
		self['echo_request_outside'] = []
		self['echo_request_ack'] = []
		self.allowed = allowed


		#Setup checks
		layer = scapy.layers.inet6.ICMPv6NDOptRedirectedHdr
		if mtu:
			layer = scapy.layers.inet6.ICMPv6PacketTooBig

		if self.allowed:
			self.register_check(checks.thc_checks.CheckRedir6(parent = self, layer = layer))
		else:
			self.register_check(checks.generic_field_check.GenericFieldCheck(layer = layer))



		#Setup action
		self.register_pass(actions.logaction.LogAction(message = "(Malicious) ICMPv6 Router redirect / MTU detected"))


	def _do_execute(self):
		# Clean up the response cache
		self['responses'] = []
