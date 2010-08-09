#				    _ _           _      _ 
#	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
#	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
#	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
#	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
#
#
# 	Copyright 2010 Georg Wicherski, <gw@mwcollect.org>
#
#
#	This file is part of mwcollectd.
#
#	mwcollectd is free software: you can redistribute it and/or modify
#	it under the terms of the GNU Lesser General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	mwcollectd is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU Lesser General Public License for more details.
#
#	You should have received a copy of the GNU Lesser General Public License
#	along with mwcollectd. If not, see <http://www.gnu.org/licenses/>.
#

from mwcollectd import *
from random import randint


class SmtpConnection(NetworkEndpoint):
	def __init__(self):
		self.buffer = bytearray()

		self.hostname = [ randint(ord('a'), ord('z')) for i in range(14) ]
		self.hostname = b'mail.' + bytes(self.hostname) + b'.com'

		self.sender = None
		self._from = None
		self.rcpt = [ ]

		self.data = b''
		self.dataState = False


	def connectionEstablished(self):
		self.timeouts.sustain = 15
		self.send(b'220 ' + self.hostname + b' Simple Mail Transfer Service Ready\r\n')

	def connectionClosed(self):
		pass

	def dataRead(self, data):
		self.buffer += data

		while True:
			off = self.buffer.find(b'\r\n')

			if off >= 0:
				self.processLine(bytes(self.buffer[:off]))
				del self.buffer[:off+2]
			else:
				break


	def processLine(self, line):
		command = line.split(b' ')[0].upper()

		if self.dataState:
			if line == b'.':
				self.dataState = False
				self.send(b'250 Ok\r\n')
				log(L_INFO, repr( (self.data,self._from,self.rcpt) ))
			else:
				self.data += line + b'\r\n'

			return

		if command == b'HELO':
			self.send(b'250 ' + self.hostname + b'\r\n')
			self.sender = line[5:]
		elif command == b'MAIL':
			self.send(b'250 Ok\r\n')
			self._from = line[10:]
		elif command == b'RCPT':
			self.send(b'250 Ok\r\n')
			self.rcpt.append(line[8:])
		elif command == b'DATA':
			self.send(b'354 Ok\r\n')
			self.dataState = True
		elif command == b'RSET':
			self._from = None
			self.rcpt = [ ]
			self.data = b''
			self.send(b'250 Ok\r\n')
		elif command == b'NOOP':
			self.send(b'250 Ok\r\n')
			self.timeouts.kill = 30
		elif command == b'QUIT':
			self.send(b'221 ' + self.hostname + b' closing connection')
			self.close()
		else:
			self.send(b'500 Syntax error, command unrecognized\r\n')
			log(L_CRIT, 'Unknown SMTP command: ' + repr(line))


def start(config):
	global smtp_server
	smtp_server = NetworkServer(('any', 25), SmtpConnection)

	return True


def stop():
	global smtp_server
	smtp_server.close()

	return True
