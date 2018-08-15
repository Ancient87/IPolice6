#!/usr/bin/python

from xml.dom import minidom
import ipolice6
import re
from ipolice6 import logger
from errors import *
from conf import *
import sys
import pdb

class ConfigParser():
	''' This is used to parse and create an IPolice6 configuration as specified by XML'''

	def __init__(self):
		self.text = 0
		self.environment_stack = []
		self.bindings = {}
	
	def _get_attribute(self, node, key="id"):
		if key in node.attributes.keys():
			return node.attributes[key]
		return None

	def _parse_node(self, node):
		'''Generic dispatcher function, this will automagically know how to deal with a XML Element'''
		try:
			parse_method = getattr(self, "_parse_%s" % node.tagName)
		except AttributeError:
				if self.text:
					parse_method = self._parse_text
				else:
					return None
		
		return parse_method(node)
	
	def parse_file(self, conf="configs/startup_config.conf"):
		'''This method will attempt to parse the file specified by conf and return the resulting ipolice6 configuration'''
		from xml.dom import minidom
		print "CONF:"+conf
		# read file
		file = open(conf)
		xmlstring = file.read()
		import re
		
		#Remove whitespaces and new lines
		xmlstring = re.sub("\n\t*", "", xmlstring)
		#print xmlstring
		xmldoc = minidom.parseString(xmlstring)
		xmldoc

		res = self._parse_node(xmldoc.documentElement)	
		return res

	def _parse_eval(self, node):
		'''Deals with eval nodes in the XML by evaluating the childnode and returns the result'''
		self.text = 1
		for child in node.childNodes:
			res = self._parse_node(node.firstChild)
			print res
			#pdb.set_trace()
			try:
				res = eval(res)

			except NameError:
				print "Sorry can't find specified Plugin, importing and module and retrying"
				#pdb.set_trace()
				import re
				#  Use regex to work out which module the Class resides in
				exp = re.compile(r"([^.]*.*)(\..*$)")
				matcher = exp.match(res)
				stmt = "import %s" % matcher.group(1)
				print stmt
				exec stmt
				try:
					res = eval(res)	
				except NameError:
					raise UnknownPluginError()
		self.text = 0
		return res

	def _parse_text(self, node):
		'''Method for parsing text nodes'''
		#pdb.set_trace()
		return str(node.data)
		#return "'"+re.sub("^u'", "", node.data)+"'"

	def _parse_type(self, node):
		''' Get the type of an object to be instantiated '''
		for child in node.childNodes:
			#pdb.set_trace()
			type = self._parse_node(child)
			return type
		return None


	def _do_component(self, node):
		'''This internal method attempts to resolve components into classes, instantiates them and configures them by parsing the child tree'''
		
		if node.__class__.__name__ == 'Text':
			if not self.text:
				return None
		bind = self._get_attribute(node)
		environment = {}
		# Instantiate it
		print node.__class__.__name__
		try:
			component_type = self._parse_type(node.getElementsByTagName("type")[0])
		except UnknownPluginError:
			print "Failed to find specified Plugin, Check your Import paths: %s. Aborting" % (node.toXML())
			sys.exit(1)

		if not component_type:
			return None
		print component_type
		#component = eval(component_type)
		component = component_type()
		component.parent = self.environment_stack[-1]['parent']
		environment['parent'] = component
		
		# Push this component on the top of the stack
		self.environment_stack.append(environment)


		# Configure it basically
		for child in node.getElementsByTagName("init"):
			self._parse_init(child)

		# Do advanced (unique) configuration
		for child in node.childNodes:
			self._parse_node(child)

		# Remove component from stack
		self.environment_stack.pop()
		self.bindings[bind] = component
		return component		


	def _parse_config(self, node):
		'''Parse root of config and create an IPolice6 object'''
		self.ipolice = ipolice6.IPolice6()
		environment = {}
		environment['parent'] = self.ipolice
		self.environment_stack.append(environment)

		for child in node.childNodes:
			self._parse_node(child)

		print "BUILT CONFIG"
		return self.ipolice

	def _parse_capturers(self, node):
		'''Parse capturers element'''
		environment = self.environment_stack[-1]
		parent = environment['parent']

		for capturer in node.childNodes:
			cap = self._do_component(capturer)
			if cap:
				parent.register_capturer(cap)

			
		return environment

	def _parse_init_arg(self, node):
		'''Parse init arg elements'''
		key = ""
		value = ""
		for child in node.childNodes:
			key = node.tagName
			self.text = 1
			value = self._parse_node(node.firstChild)	
			self.text = 0
		return (key, value) 


	def _parse_init(self, node):
		'''Parse init element'''
		print node
		parent = self.environment_stack[-1]['parent']
		import pdb
		#print node.childNodes
		#pdb.set_trace()
		for init_arg in node.childNodes:
			print init_arg
			(key, value) = self._parse_init_arg(init_arg)
			if not key is None and not key is None and not key is "":
				print "Assigning %s to %s" % (key, value)
				tmp = "parent.%s" % key
				#pdb.set_trace()
				stmt = tmp+ "= value"
				print stmt
				exec stmt
	
	def _parse_checks(self, node):
		'''Parse checks element'''
		#pdb.set_trace()
		parent = self.environment_stack[-1]['parent']
		for check in node.childNodes:
			component = self._do_component(check)
			if component:
				parent.register_check(component)
		return None


	def _parse_modules(self, node):
		'''Parse modules element'''
		parent = self.environment_stack[-1]['parent']
		for module in node.childNodes:
			mod = self._do_component(module)
			if module:
				parent.register_module(mod)	
		return None

	def _parse_actions(self, node):
		'''Parse actions element'''
		parent = self.environment_stack[-1]['parent']
		for check in node.childNodes:
			action = self._do_component(check)
			if action:
				import pdb
				#pdb.set_trace()
				parent.register_pass(action)
		return None


#If this is invoked as main loads config and starts
if __name__ == "__main__":
	configfile = "configs/startup_config.conf"
	if len(sys.argv) > 1:
		configfile = sys.argv[1]

	parser = ConfigParser()
	conf = parser.parse_file(configfile)
	
	pdb.set_trace()
	conf.start()

	try:
		while 1:
			pass
	except KeyboardInterrupt:
		print "Shutting down"
		conf.stop()
		conf.join()
		print "All threads done, closing main app"
		sys.exit(1)
