from mwcollectd import *

class TimeoutUser:
	def __init__(self):
		self.timeout = Timeout(5, self.handleTimeout)
#		self.timeout = Timeout(1, self.handleTimeout)
		self.racer = Timeout(3, self.handleTimeout)

	def handleTimeout(self, timeout):
		if timeout == self.timeout:
			log(L_INFO, 'Unexpected timeout occured; ' + repr(self))
		elif timeout == self.racer:
			del self.timeout
			del self.racer

def start():
	global tu
	tu = TimeoutUser()

	return True

def stop():
	global tu
	del tu

	return True
