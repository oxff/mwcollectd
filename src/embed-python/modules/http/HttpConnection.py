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
from urllib.parse import urlparse, parse_qs


class HttpConnection(NetworkEndpoint):
	HTTP_STATE_REQUEST = 0
	HTTP_STATE_HEADERS = 1
	HTTP_STATE_BODY = 2
	
	HTTP_METHODS = [
		b'GET',
		b'POST',
		b'HEAD',
	]

	HTTP_PROTOCOLS = [b'HTTP/1.0', b'HTTP/1.1']


	def connectionEstablished(self):
		self.timeouts.sustain = 15

		self.state = self.HTTP_STATE_REQUEST
		self.buffer = bytearray()
		self.headers = { }


	def connectionClosed(self):
		pass

	def dataRead(self, buf):
		self.buffer += buf

		while len(self.buffer) > 0:
			if self.state == self.HTTP_STATE_REQUEST:
				offset = self.buffer.find(b'\r\n')

				if offset >= 0:
					request = [bytes(elem) for elem in self.buffer[0:offset].split(b' ') if len(elem) > 0]
					del self.buffer[:offset + 2]
					self.state = self.HTTP_STATE_HEADERS

					if len(request) != 3 or request[0] not in self.HTTP_METHODS:
						log(L_CRIT, "Invalid request method: " + repr(request))
						self.send(request[2] + b' 501 Not implemented\r\nConnection: close\r\n\r\n')
						self.close()
						return
					elif request[2] not in self.HTTP_PROTOCOLS:
						log(L_CRIT, "Unknown HTTP protocol: " + repr(request))
						self.send(b'HTTP/1.1 505 HTTP Version not supported\r\nConnection: close\r\n\r\n')
						self.close()
						return

					(self.method, self.path, self.protocol) = request
					self.currentHeader = None
				else:
					return

			elif self.state == self.HTTP_STATE_HEADERS:
				offset = self.buffer.find(b'\r\n')

				if offset >= 0:
					header = self.buffer[0:offset]
					del self.buffer[:offset + 2]

					if header.startswith(b' ') or header.startswith(b'\t'):
						self.currentHeader += b' ' + header.lstrip()
					else:
						if self.currentHeader:
							try:
								(name, separator, value) = self.currentHeader.partition(b':')

								for i in range(len(value)):
									if value[i] == ord(b'\t'):
										value[i] = ord(b' ')

								self.headers[bytes(name).lower()] = bytes(value.strip())
							except:
								pass

						if len(header) > 0:
							self.currentHeader = header
						else:
							del self.currentHeader
							self.state = self.HTTP_STATE_BODY
							self.processRequest()
							return
				else:
					return


	def processRequest(self):
		self.path = urlparse(self.path.decode('latin1'))
		self.query = parse_qs(self.path.query)

		response = ''

		for key in self.query.keys():
			if self.query[key][0].find('http://') >= 0:
				response += self.query[key][0] + '\r\n'

		response = response.encode('utf8')

		self.send(self.protocol + b' 200 Ok\r\nConnection: close\r\nContent-type: text/plain; charset=utf-8\r\n'
				+ b'\r\nFoobar: ' + response)
		self.close()
		return

