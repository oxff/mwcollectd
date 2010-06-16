from mwcollectd import *


def shizzle():
	log(L_INFO, "This is nice foobar!")
	log(L_INFO, "And now we log something with no prefix, eventhough in connection context!", True)

class Connection(NetworkEndpoint):
	def connectionEstablished(self):
		shizzle()


def start():
	global srv
	srv = NetworkServer( ('any', 1337), Connection)

	return True

def stop():
	global srv
	srv.close()

	return True
