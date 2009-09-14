from mwcollectd import *

class Logger(object):
	def __init__(self, prefix):
		self.prefix = prefix

	def debug(self, msg, *args, ** kwargs):
		log(L_SPAM, '[Py/' + self.prefix + '] ' + (msg % args))

	def warning(self, msg, *args, ** kwargs):
		log(L_INFO, '[Py/' + self.prefix + '] ' + (msg % args))

	def info(self, msg, *args, ** kwargs):
		log(L_INFO, '[Py/' + self.prefix + '] ' + (msg % args))
	
	def critical(self, msg, *args, ** kwargs):
		log(L_CRIT, '[Py/' + self.prefix + '] ' + (msg % args))
