from mwcollectd import *


class ShellcodeProcessHandler:
	def __init__(self, name, event):
		if 'commandline' not in event or 'recorder' not in event:
			return

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
			log(L_SPAM, '  ' + repr(command))

			if command[0] == 'tftp' or command[0] == 'tftp.exe':
				(url, localfile) = self.url_TFTP(command[1:])

				if url:
					dispatchEvent('shellcode.download', { 'url': url,
						'localfile': localfile, 'recorder': recorder } )

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
