from mwcollectd import *


class ShellcodeProcessHandler:
	def __init__(self, name, event):
		if 'commandline' not in event or 'recorder' not in event:
			return

		self.vfiles = { }

		self.parse( event['commandline'].decode('latin1'), event['recorder'] )


	def parse(self, cmd, recorder):
		commands = [ ]
		curr = ''
		escaping = False
		separators = frozenset( ['|', '&'] )

		for c in cmd:
			if not escaping:
				if c == '^':
					escaping = True
				elif c in separators:
					if len(curr) > 0:
						commands.append(curr)
						curr = ''
				else:
					curr += c
			else:
				curr += c
				escaping = False

		if len(curr) > 0:
			commands.append(curr)

		parsed_commands = [ ]

		for cmd in commands:
			quoter = None
			quotes = frozenset( ["'", '"'] )
			separators = frozenset( [' ', '\t', ',', ';'] )
			curr = ''
			ccmd = [ ]

			for c in cmd:
				if not quoter:
					if c in quotes and len(curr) == 0:
						quoter = c
					elif c in separators:
						if len(curr) > 0:
							ccmd.append(curr)
							curr = ''
					else:
						curr += c
				else:
					if c == quoter:
						quoter = None
					else:
						curr += c

			if len(curr) > 0:
				ccmd.append(curr)

			parsed_commands.append(ccmd)

		return self.emulate(parsed_commands, recorder)


	def emulate(self, commands, recorder):
		for command in commands:
			if command[0] == 'tftp' or command[0] == 'tftp.exe':
				(url, localfile) = self.url_TFTP(command[1:])

				if url:
					dispatchEvent('shellcode.download', { 'url': url,
						'localfile': localfile, 'recorder': recorder } )
			elif command[0] == 'cmd' and len(command) > 2 and command[1] == '/c':
				self.emulate([command[2:]], recorder)
			elif command[0] == 'echo':
				line = ''

				for word in command[1:]:
					if word == '>':
						self.vfiles[command[-1]] = line + '\n'
					elif word == '>>':
						self.vfiles[command[-1]] += line + '\n'
					else:
						if line != '':
							line += ' '

						line += word
			elif command[0] == 'ftp' or command[0] == 'ftp.exe':
				for param in command[1:]:
					if param[:3] == '-s:':
						instrs = self.vfiles[param[3:]].split('\n')

						host = None
						port = 21
						user = 'anonymous'
						passwd = 'secret'

						for instr in instrs:
							w = instr.split(' ')

							if w[0] == 'open':
								host = w[1]
								port = int(w[2])
							elif w[0] == 'user':
								user = w[1]

								if len(w) >= 3:
									passwd = w[2]
							elif w[0] == 'get':
								filename = ' '.join(w[1:])

								if filename[:1] == '/':
									filename = filename[1:]

								url = 'ftp://%s:%s@%s:%i/%s' % (user, passwd, host, port, filename)
								log(L_SPAM, 'FTP Download via shell: ' + url)

	def url_TFTP(self, command):
		while len(command) > 0 and command[0][0] == '-':
			command = command[1:]

		if len(command) != 3:
			return None

		if command[1] not in ['get', 'put']:
			return None

		return ('tftp://' + command[0] + '/' + command[2], command[2])


def start():
	global process_handler
	process_handler = EventSubscription('shellcode.process', ShellcodeProcessHandler)
	return process_handler.register()


def stop():
	global process_handler
	return process_handler.unregister()
