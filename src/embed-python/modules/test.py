from mwcollectd import *
import sys
import struct

class SmbConnection(NetworkEndpoint):
	def connectionEstablished(self):
		log(L_INFO, 'New connection...')

	def connectionClosed(self):
		log(L_INFO, 'Connection has been closed.')

	def dataRead(self, buf):
		log(L_SPAM, buf.decode('latin1').replace('\r\n', '').replace('\n', ''))


def start():
	global smb_server
	smb_server = NetworkServer(('any', 31337), SmbConnection)

	return True


def stop():
	global smb_server
	smb_server.close()

	return True
