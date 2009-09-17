from mwcollectd import *
import mwcollectd
import sys
import struct

class SmbConnection(NetworkEndpoint):
	def connectionEstablished(self):
		self.timeouts.sustain = 5
		log(L_INFO, 'New connection, timeout after %is idle time.' % self.timeouts.sustain)

	def connectionClosed(self):
		log(L_INFO, 'Connection has been closed.')

	def dataRead(self, buf):
		log(L_SPAM, buf.decode('latin1').replace('\r\n', '').replace('\n', ''))


def start():
	log(L_INFO, mwcollectd.version)

	global smb_server
	smb_server = NetworkServer(('any', 1337), SmbConnection)

	dispatchEvent('python.test', { 'foo': 'bar', 'number': 42 })

	return True


def stop():
	global smb_server
	smb_server.close()

	return True
