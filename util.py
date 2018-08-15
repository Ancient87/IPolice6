#!/usr/bin/python

import sys

class StdOutDummy():
	''' Class needed for the capturing the ouptut of the scapy show() method '''
        def __init__(self, loc=""):
		self.loc = loc

	def write(self, text):
		self.loc = self.loc + text

	def clear(self):
		self.loc = ""

	def enable(self):
		'''Redirect stdout to me'''
		self.bu = sys.stdout
		sys.stdout = self
		sys.stderr = self
	def disable(self):
		'''Restore stdout'''
		sys.stdout = self.bu
		sys.stderr = sys.__stderr__

def has_function(object, functionname):
	''' Utility function that checks if an object exposes the required function '''
	func = getattr(object, functionname)
	if func and callable(func):
		return 1
	return 0

def fulfills_interface(object, target):
	''' Utility function that checks if a given object has (at least) the same functions as another '''

	# Functions needed 
	required = dir(target)
	for attribute in required:
		if not hasattr(object, attribute):
			return 0
	return 1


import socket
import fcntl
import struct
from scapy.all import RandMAC
import re


def get_ip6_padded(src = "::"):
	''' Utility function that expands an abbreviated IPv6 address into full notation'''
	temp = src.split(":")
	import re
	if "::" in src:
		#print "matches "+src
		amount = src.count(":")
		add = 7 - amount
		replacepattern = "::"+amount*':'
		src = re.sub("::", replacepattern, src)
		temp = src.split(":")

	temp = [x.zfill(4) for x in temp]
	#print str(temp)
	maximum = min(len(temp), 8)
	res = ""
	for i in range(0,maximum):
		if i < maximum-1:
			append = ":"
		else:
			append = ""
		res = res + temp[i] + append
	return res

def get_ip6_short(src = "::"):
	'''Utility function that attempts to abbreviate a given IP6 address as much as possible'''
	#step 1 remove leading 0's
	src = re.sub(":0+([^0^:])", ":\\1",src)
	#step 2 find groups of consecutive 0's
	list = re.findall("(0+:?)+", src)
	#step 3 find longest group
	group = ""
	for g in list:
		if len(g) > len(group):
			group = g
	if len(group) > 2:
		src = re.sub(group,":", src)
		src = re.sub(":::","::", src)
	return src

def get_ip6_address(groups = 8, padded = False):
	'''Utility function to get the public IP6 Address of an interface'''
	s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
	try:
		s.connect(("ipv6.google.com", 80))
	except socket.error:
		s.connect(("ipv6.he.net", 80))

	import re
	fullip = s.getsockname()[0]
	fullip = get_ip6_padded(fullip)
	if(groups >= 8 or groups < 1):
		res = fullip
	else:
		res = re.match("([0-9a-f]*::?){%d}[0-9a-f]*" % (groups-1), fullip).group(0)
	if(padded):
		res = get_ip6_padded(res)
	else:
		res = get_ip6_short(res)
	return res






def get_ip6_prefix(length = 4):
	'''Small utility function that ptovides the ip prefix of the network'''
	return re.sub("::::", "::", get_ip6_address(length)+"::")
	#return get_ip6_padded(get_ip6_address(4)+"::")[0:19]



def get_random_ip6_address(eui64 = 1, prefix = get_ip6_address(groups = 4, padded = True)):
	'''Creates a random ip6 address for a given prefix'''
	mac = "%s" % (RandMAC())
	(first, second, third, fourth, fifth, sixth) = mac.split(":")
	if(eui64):
		host = first+second+":"+third+"ff:"+"fe"+fourth+":"+fifth+sixth
	else:
		host = str(RandIP6())[len(RandIP6())/2:len(RandIP6())]
	return get_ip6_padded(prefix+":"+host)





def get_ethernet_solicitated_multicast(src = get_ip6_address()):
	''' Produces the Layer 2 multicast address '''
	#Format is 33:33:ff:last 24 bytes of ipv6 address
	#extract last part of address
	second = src.split(":")[6:8] #Get last two groups
	second = [group.zfill(4) for group in second] # Pad to usefull length
	second = second[0][2:4]+":"+second[1][0:2]+":"+second[1][2:4]
	mac = "33:33:ff:"+second
	return mac

def get_ip6_solicitated_multicast(src = get_random_ip6_address()):
	'''Computes and returns a solicitated multicast ip6 for the given ip'''
	# ff02::1:ffxx:xxxx (where x is last 6 hex from ip6
	second = src.split(":")[6:8] #Get last two groups
	second = [group.zfill(4) for group in second] # Pad to usefull length
	second = second[0][2:4]+":"+second[1]
	ip = "ff02::1:ff"+second
	#print ip
	res = get_ip6_padded(ip)
	#print "returning"+res
	return res
