from mwcollectd import *

class Connection(NetworkEndpoint):
	def connectionEstablished(self):
		self.timeouts.sustain = 5
		self.buffer = b''

		log(L_INFO, 'New curl shell connection, timeout after %is idle time.' % self.timeouts.sustain)

	def connectionClosed(self):
		pass

	def dataRead(self, buf):
		self.buffer += buf
		pos = self.buffer.find(b'\n')

		if pos >= 0:
			log(L_SPAM, 'Download URL \"%s\".' % self.buffer[:pos].decode('utf8'))
			dispatchEvent('shellcode.download', { 'url': self.buffer[:pos].decode('utf8'), 'recorder': self.getRecorder() } )
			self.buffer = self.buffer[pos+1:]


def start(config):
	global server
	server = NetworkServer(('any', 8080), Connection)

	return True


def stop():
	global server
	server.close()

	return True
