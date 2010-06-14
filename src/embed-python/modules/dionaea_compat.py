import mwcollectd

class Logger(object):
	def __init__(self, prefix):
		self.prefix = prefix

	def debug(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_SPAM, '[Py/' + self.prefix + '] ' + (msg % args))

	def warning(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_INFO, '[Py/' + self.prefix + '] ' + (msg % args))

	def info(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_INFO, '[Py/' + self.prefix + '] ' + (msg % args))
	
	def critical(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_CRIT, '[Py/' + self.prefix + '] ' + (msg % args))

class connection(mwcollectd.NetworkEndpoint):
	def __init__(self, conntype):
		mwcollectd.NetworkEndpoint.__init__(self)

	def connectionClosed(self):
		self.connectionLost()

	def processors(self):
		pass
