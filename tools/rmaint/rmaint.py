#!/usr/bin/python

import sys, getopt, getpass, socket, threading, glob, re
import paramiko
from select import select
from os.path import basename


def usage():
	sys.stderr.write(
"""Usage: %s [options] <action> <host:port> [<host:port> ...]
   -u <username>	Use <username> for login
   -k <filename>	Use private key file <filename> besides keys in  ~/.ssh
   -p <password>	Use <password> for login
   -C <configlob>	Push all configuration files matching <confglob>
Possible actions are:
   clear                Remove all source directories (does not touch bins)
   fetch                Create source directories and fetch latest from GIT
   deps                 Install build- & runtime dependencies (Ubuntu specific)
   autoconf             autoreconf; configure
   build                make; make install
   up                   Check if mwcollectd is running and if not start it
   restart		Send SIGINT to all mwcollectd processes, then run 'up'
   conf                 Upload configuration from local host
   log			Download the mwcollectd.log file from all hosts.
   clearlog		Empty the mwcollectd logfile on all hosts.
""" % sys.argv[0])
	sys.exit(0)


class SshThread(threading.Thread):
	def __init__(self, client, name):
		threading.Thread.__init__(self)
		self.client = client
		self.name = name
	
	def execute(self, command):
		(stdout, stdin, stderr) = self.client.exec_command(command)

		out, err = '', ''

		while True:
			if stdout.channel.recv_ready():
				buff = stdout.channel.recv(1024)
				out += buff

				if buff == '':
					break

			if stderr.channel.recv_stderr_ready():
				err += stderr.channel.recv_stderr(1024)

			if stdout.channel.exit_status_ready():
				break
			
			(readset, writeset, excset) = select([stdout.channel], [], [stdout.channel])
			
			if stdout.channel in excset:
				break
		
		return (out, err)


class ClearThread(SshThread):
	def run(self):
		for project in ['libnetworkd', 'libemu', 'mwcollectd']:
			print '\n'.join(self.execute('rm -rf /usr/src/' + project + '/'))


class FetchThread(SshThread):	
	def run(self):
		for project in ['libnetworkd', 'libemu', 'mwcollectd']:
			print 'Fetching %s on %s ...' % (project, self.name)
			print '\n'.join(self.execute('mkdir -p /usr/src/$NAME$; cd /usr/src/$NAME$; git init; git remote add origin http://git.mwcollect.org/$NAME$; git pull origin master'.replace('$NAME$', project)))

class DependenciesThread(SshThread):
	def run(self):
		print 'Installing dependencies on %s ...' % self.name
		print '\n'.join(self.execute('apt-get -yq install git-core gcc g++ make automake autoconf autotools-dev libcurl4-openssl-dev libnetfilter-queue-dev python3 python3-dev libtool libudns-dev'))

class AutoconfThread(SshThread):
	def run(self):
		for project in ['libnetworkd', 'libemu']:
			print 'Configuring %s on %s ...' % (project, self.name)
			print '\n'.join(self.execute('cd /usr/src/$NAME$; autoreconf -vi; ./configure --prefix=/opt/$NAME$'.replace('$NAME$', project)))
		print 'Configuring mwcollectd on %s ...' % self.name
		print '\n'.join(self.execute('cd /usr/src/$NAME$; autoreconf -vi; ./configure --prefix=/opt/$NAME$ --with-libnetworkd=/opt/libnetworkd --with-libemu=/opt/libemu'.replace('$NAME$', 'mwcollectd')))

class BuildThread(SshThread):
	def run(self):
		for project in ['libnetworkd', 'libemu', 'mwcollectd']:
			print 'Building %s on %s ...' % (project, self.name)
			print '\n'.join(self.execute('cd /usr/src/$NAME$; make; make install'.replace('$NAME$', project)))

class PushConfThread(SshThread):
	def run(self):
		sftp = self.client.open_sftp()

		for file in glob.iglob(self.configdir):
			print 'Transfering %s to %s...' % (basename(file), self.name)
			sftp.put(file, '/opt/mwcollectd/etc/mwcollectd/' + basename(file))

class CheckUpThread(SshThread):
	def run(self):
		(out, err) = self.execute('ps aux | grep mwcollectd')
		instances = [ line for line in out.split('\n') if line.find('/sbin/mwcollectd') >= 0 ]
		
		if instances != [ ]:
			print 'Already running on %s: %s' % (self.name, instances[0])
		else:
			print 'Starting on %s:' % self.name
			print  '\n'.join(self.execute('cd /opt/mwcollectd; ./sbin/mwcollectd -c etc/mwcollectd/mwcollectd.conf'))


class RestartThread(CheckUpThread):
	def run(self):
		self.execute('killall -SIGINT mwcollectd')

		CheckUpThread.run(self)


class GetLogThread(SshThread):
	def run(self):
		sftp = self.client.open_sftp()

		sftp.get('/opt/mwcollectd/var/log/mwcollectd/mwcollectd.log', 'mwcollectd-%s.log' % self.name.replace('.', '_'))

class ClearLogThread(SshThread):
	def run(self):
		self.execute('echo \'\' > /opt/mwcollectd/var/log/mwcollectd/mwcollectd.log')

if __name__ == '__main__':
	username = getpass.getuser()
	key = None
	password = None
	configdir = None

	try:
		(options, servers) = getopt.getopt(sys.argv[1:], 'k:p:u:C:')
		action = servers[0]
		servers = servers[1:]
	except IndexError:
		usage()
	except getopt.GetoptError:
		usage()

	for option in options:
		if option[0] == '-k':
			key = option[1]
		elif option[0] == '-p':
			password = option[1]
		elif option[0] == '-u':
			username = option[1]
		elif option[0] == '-C':
			configdir = option[1]

	if not len(servers):
		sys.stderr.write("You have to specify at least one server.\n")
		usage()

	for i in xrange(len(servers)):
		servers[i] = servers[i].split(':')[:2]

		servers[i] = tuple(servers[i])

	modes = {
			'clear': ClearThread,
			'fetch': FetchThread,
			'deps': DependenciesThread,
			'autoconf': AutoconfThread,
			'build': BuildThread,
			'up': CheckUpThread,
			'restart': RestartThread,
			'conf': PushConfThread,
			'log': GetLogThread,
			'clearlog': ClearLogThread,
		}

	if action not in modes:
		usage()

	if action == 'conf' and not configdir:
		usage()

	threads = [ ]

	for server in servers:
		client = paramiko.SSHClient()
		client.load_system_host_keys()
		port = (len(server) == 2) and int(server[1]) or 22

		try:
			client.connect(server[0], port = port, username = username, password = password, key_filename = key)
		except paramiko.SSHException, e:
			sys.stderr.write("Could not authenticate to %s: %s\n" % (repr(server), repr(e)))
			sys.exit(-1)
		except socket.error, e:
			sys.stderr.write("Could not connect to %s: %s\n" % (repr(server), repr(e)))
			sys.exit(-1)

		t = modes[action](client, server[0])

		if configdir:
			t.configdir = configdir

		t.start()
		threads.append(t)


	for thread in threads:
		thread.join()

	sys.exit(0)
