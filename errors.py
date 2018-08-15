#!/usr/bin/python

#Defines a bunch of Errors to be used in the framework

class NotAnActionError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repor(self.value)

class NotACapturerError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)

class NotAModuleError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repor(self.value)

class UnknownPluginError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repo(self.value)
