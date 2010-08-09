import mwcollectd

class Logger(object):
	def __init__(self, prefix):
		self.prefix = prefix

	def debug(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_SPAM, '[Py/' + self.prefix + '] ' + msg + ' '.join(args))

	def warning(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_INFO, '[Py/' + self.prefix + '] ' + msg + ' '.join(args))

	def warn(self, *args, ** kwargs):
		self.warning(*args, **kwargs)

	def info(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_INFO, '[Py/' + self.prefix + '] ' + msg + ' '.join(args))
	
	def critical(self, msg, *args, ** kwargs):
		mwcollectd.log(mwcollectd.L_CRIT, '[Py/' + self.prefix + '] ' + msg + ' '.join(args))

conn_logger = Logger('connection compat')

class connection(mwcollectd.NetworkEndpoint):
	def __init__(self, conntype):
		mwcollectd.NetworkEndpoint.__init__(self)
		self.buf = b''

	def connectionClosed(self):
		self.handle_disconnect()

	def processors(self):
		pass

	def dataRead(self, data):
		r = self.handle_io_in(self.buf + data)
		self.buf = (self.buf + data)[r:]
		if len(self.buf) > 1024**2:
			self.close()

	def connectionEstablished(self):
		self.handle_established()

	def close(self):
		conn_logger.debug('close called')
		mwcollectd.NetworkEndpoint.close(self)

incident_logger = Logger('incident compat')

class incident:
	def __init__(self, path):
		self.path = path
		self.dict = {}

	def __setattr__(self, name, value):
		self.dict[name] = value

	def __getattr__(self, name):
		return self.dict[name]

	def report(self):
		incident_logger.debug('incident reported: path %s dict %s' % (self.path, str(self.dict)))


