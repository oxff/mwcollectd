/*
 *   __              __                                               __
 *  /\ \            /\ \__                                           /\ \
 *  \ \ \____    ___\ \ ,_\   ____    ___     ___     ___   _____    \_\ \
 *   \ \ '__`\  / __`\ \ \/  /',__\ /' _ `\  / __`\  / __`\/\ '__`\  /'_` \
 *    \ \ \L\ \/\ \L\ \ \ \_/\__, `\/\ \/\ \/\ \L\ \/\ \L\ \ \ \L\ \/\ \L\ \
 *     \ \_,__/\ \____/\ \__\/\____/\ \_\ \_\ \____/\ \____/\ \ ,__/\ \___,_\
 *      \/___/  \/___/  \/__/\/___/  \/_/\/_/\/___/  \/___/  \ \ \/  \/__,_ /
 *                                                            \ \_\
 *                                                             \/_/
 *
 * interface-irc.hpp - control botsnoopd like an irc bot
 *
 * This work is (c) 2007 by Georg Wicherski, intellectual property of its
 * respective author and published under the terms given in the README file.
 *
 */

#include "log-irc.hpp"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fnmatch.h>
#include <time.h>
#include <ctype.h>
#include <string>
#include <sstream>
#include <iomanip>


IrcInterfaceModule::IrcInterfaceModule(Daemon * daemon)
{
	m_daemon = daemon;
	m_connection = 0;
}


bool IrcInterfaceModule::start(Configuration * moduleConfiguration)
{
	string::size_type pos;
	string server;
	
	m_unloading = false;

	server = moduleConfiguration->getString(":network:server",
		"irc.freenode.org");

	if((pos = server.find(":")) != string::npos)
	{
		m_remoteNode.name = server.substr(0, pos);
		m_remoteNode.port = (uint16_t) strtoul(server.substr(pos + 1).c_str(),
			0, 0);
	}
	else
	{
		m_remoteNode.name = server;
		m_remoteNode.port = 6667;
	}

	m_configuration.password = moduleConfiguration->getString(
		":network:password", "");

	m_configuration.nickname = moduleConfiguration->getString(
		":network:nickname", "mwcollectd-%");
	m_configuration.ident = moduleConfiguration->getString(
		":network:ident", "mwcollectd");
	m_configuration.realname = moduleConfiguration->getString(
		":network:realname", "http://www.mwcollect.org/");

	m_configuration.channel = moduleConfiguration->getString(
		":network:channel", "#mwcollectd");
	m_configuration.key = moduleConfiguration->getString(
		":network:key", "");

	m_configuration.administrators = moduleConfiguration->getStringList(
		":administrators");

	if((pos = m_configuration.nickname.find("%")) != string::npos)
	{
		char hostname[64];

		if(gethostname(hostname, sizeof(hostname)) != 0)
		{
			LOG("Could not obtain hostname: %s!", strerror(errno));
			return false;
		}

		m_configuration.nickname = m_configuration.nickname.substr(0, pos)
			+ hostname + m_configuration.nickname.substr(pos + 1);
	}

	m_daemon->getNameResolvingFacility()->resolveName(m_remoteNode.name, this);

	m_loggingEnabled = false;
	enableLogging(moduleConfiguration->getString(":startup-logging", "")
		== string("on"));

	return true;
}

void IrcInterfaceModule::enableLogging(bool enable)
{
	if(enable && !m_loggingEnabled)
		m_daemon->getLogManager()->addLogFacility(this);
	else if(!enable && m_loggingEnabled)
		m_daemon->getLogManager()->removeLogFacility(this);

	m_loggingEnabled = enable;
}

const char * IrcInterfaceModule::getTarget()
{
	static char buffer[128];

	snprintf(buffer, sizeof(buffer) -1, "%s on %s",
		m_configuration.channel.c_str(), m_remoteNode.name.c_str());
	buffer[sizeof(buffer) - 1] = 0;

	return buffer;
}

void IrcInterfaceModule::logMessage(const char * renderedMessage)
{
	if(m_connection)
		m_connection->logMessage(renderedMessage);
}

void IrcInterfaceModule::childDied(IrcConnection * conn)
{
	if(conn != m_connection)
		return;

	m_connection = 0;
	
	if(!m_unloading)
	{
		m_daemon->getNameResolvingFacility()->
			resolveName(m_remoteNode.name, this);
	}
	else
		m_daemon->stop();
}

void IrcInterfaceModule::nameResolved(string name, list<string> addresses,
	NameResolutionStatus status)
{
	NetworkNode remoteNode;
	IrcConnection * connection;
	NetworkSocket * socket;

	if(m_remoteNode.name != name || m_connection)
		return;

	remoteNode.name = addresses.front();
	remoteNode.port = m_remoteNode.port;

	connection = new IrcConnection(m_daemon, this, &m_configuration);

	if(!(socket = m_daemon->getNetworkManager()->connectStream(&remoteNode,
		(NetworkEndpoint *) connection)))
	{
		LOG("Failed to connect to %s:%hu (%s:%hu) for log-irc!",
			m_remoteNode.name.c_str(), m_remoteNode.port,
			remoteNode.name.c_str(), remoteNode.port);

		return;
	}

	m_connection = connection;
	connection->setSocket(socket);
}

bool IrcInterfaceModule::stop()
{
	m_daemon->getNameResolvingFacility()->cancelResolutions(this);
	
	m_unloading = true;

	if(m_loggingEnabled)
	{
		m_daemon->getLogManager()->removeLogFacility(this);
		m_loggingEnabled = false;
	}

	if(m_connection)
	{
		m_connection->quit();
		return false;
	}

	return true;
}

EXPORT_LIBNETWORKD_MODULE(IrcInterfaceModule, Daemon *);



IrcConnection::IrcConnection(Daemon * daemon, IrcInterfaceModule * parent,
		IrcConfiguration * config)
{
	m_connected = false;
	m_daemon = daemon;
	m_parent = parent;
	m_configuration = config;
	m_joined = false;
}


bool IrcConnection::quit()
{
	m_socket->send("QUIT :http://www.mwcollect.org/\r\n", 33);
	m_socket->close();
	
	return true;
}

void IrcConnection::dataRead(const char * buffer, uint32_t dataLength)
{
	string::size_type pos;

	m_buffer.append(buffer, dataLength);

	while((pos = m_buffer.find("\r\n")) != string::npos)
	{
		parseLine(m_buffer.substr(0, pos));
		m_buffer.erase(0, pos + 2);
	}
}

void IrcConnection::connectionEstablished(NetworkNode * remoteNode,
	NetworkNode * localNode)
{
	string line;

	if(!m_configuration->password.empty())
	{
		line = "PASS " + m_configuration->password + "\r\n";
		m_socket->send(line.data(), line.size());
	}

	line = "NICK " + m_configuration->nickname + "\r\n";
	m_socket->send(line.data(), line.size());

	line = "USER " + m_configuration->ident + " 0 0 :" +
		m_configuration->realname + "\r\n";
	m_socket->send(line.data(), line.size());

	m_connected = true;
}

void IrcConnection::nameResolved(string name, list<string> addresses,
		NameResolutionStatus status)
{
	if(status == NRS_OK)
	{
		stringstream line;

		line << "Resolved " << name << " to ";

		for(list<string>::iterator it = addresses.begin();
			it != addresses.end(); ++it)
		{
			line << * it << ", ";
		}

		LOG("%s.", line.str().substr(0, line.str().size() - 2).c_str());
	}
	else
	{
		LOG("Resolution of %s failed with code %i.", name.c_str(), status);
	}
}

void IrcConnection::parseLine(string line)
{
	string::size_type pos;
	string header, message;
	vector<string> words;

	if(line.substr(0, 5) == "PING ")
	{
		line = "PONG " + line.substr(5) + "\r\n";
		m_socket->send(line.data(), line.size());
		return;
	}
	else if(line.substr(0, 6) == "ERROR ")
	{
		LOG("IRC Interface server reported error: %s", line.substr(7).c_str());
		m_socket->close();
	}

	if((pos = line.find(" :")) != string::npos)
	{
		header = line.substr(0, pos);
		message = line.substr(pos + 2);
	}
	else
		header = line;

	splitWords(header.c_str(), words);

	if(words.size() < 3)
		return;

	if((words[1] == "001" || words[1] == "004" || words[1] == "005" || words[1]
		== "376") && !m_joined)
	{
		string line = "MODE " + m_configuration->nickname + " +xi\r\nJOIN " + m_configuration->channel;

		if(!m_configuration->key.empty())
			line += " " + m_configuration->key;

		line += "\r\n";

		m_socket->send(line.data(), line.size());
		m_joined = true;
	}
	else if(words[1] == "PRIVMSG")
	{
		if(* message.begin() == '.')
		{
			string from = words[0].substr(1);
			string to = words[2];

			splitWords(message.c_str(), words);
			parseCommand(from, to, words);
		}
	}
}

void IrcConnection::parseCommand(string& from, string& to, vector<string>& words)
{
	string responseDestination;

	if(!words.size())
		return;

	if(* to.begin() == '#')
		responseDestination = to;
	else
	{
		string::size_type pos;

		responseDestination = from;

		if((pos = responseDestination.find("!")) != string::npos ||
			(pos = responseDestination.find("@")) != string::npos)
			responseDestination.erase(pos);
	}

	for(unsigned int i = 1; i < words.size(); ++i)
	{
		char * buffer = new char[words[i].size() + 1];
		const char * walk = words[i].c_str();
		char * store = buffer;

		while(* walk)
		{
			if(* walk == '\\')
			{
				++walk;

				if(* walk == 'n')
					* store++ = '\n';
				else if(* walk == 'r')
					* store++ = '\r';
				else if(* walk == '\\')
					* store++ = '\\';
				else if(* walk == 'x')
				{
					char tmp[3];

					tmp[0] = * ++walk;
					tmp[1] = * ++walk;
					tmp[2] = 0;

					* store++ = (char) strtoul(tmp, 0, 0x10);
				}
				else if(* walk)
				{
					* store++ = '\\';
					* store++ = * walk;
				}

				++walk;
			}
			else
				* store++ = * walk++;
		}

		* store = 0;

		words[i] = buffer;
		delete [] buffer;
	}

	{
		string error;

		if(!checkCommand(from, words[0], error))
		{
			string line = "PRIVMSG " + responseDestination + " :" + error +
				"\r\n";
			m_socket->send(line.data(), line.size());

			return;
		}
	}

	if(words[0] == ".version")
	{
		string line = "PRIVMSG " + responseDestination + " :" +
			m_daemon->getVersion() + "\r\n";
		m_socket->send(line.data(), line.size());
	}
	else if(words[0] == ".dns")
	{
		m_daemon->getNameResolvingFacility()->resolveName(words[1], this);
	}
	else if(words[0] == ".list-modules")
	{
		string lines;

		list<ModuleEncapsulation> modules;
		m_daemon->getModuleManager()->enumerateModules(&modules);

		for(list<ModuleEncapsulation>::iterator i = modules.begin();
			i != modules.end(); ++i)
		{
			char * idstring;

			if(asprintf(&idstring, "0x%02x", i->moduleId) >= 0)
			{
				lines += "PRIVMSG " + responseDestination + " :[" + idstring +
					"] \x02" + i->moduleInterface->getName() + "\x02 - " +
					i->moduleInterface->getDescription() + "\r\n";
				free(idstring);
			}
		}

		m_socket->send(lines.data(), lines.size());
	}
	else if(words[0] == ".list-loggers")
	{
		string line;

		list<LogFacility *> loggers = m_daemon->getLogManager()
			->getLogFacilities();

		if(loggers.empty())
			line = "PRIVMSG " + responseDestination + " :No registered log "
				"facilities.\r\n";

		for(list<LogFacility *>::iterator i = loggers.begin();
			i != loggers.end(); ++i)
		{
			line += "PRIVMSG " + responseDestination + " :\x02" +
				(* i)->getName() + "\x02 - " + (* i)->getDescription() + " => "
				+ (* i)->getTarget() + "\r\n";
		}

		m_socket->send(line.data(), line.size());
	}
	else if(words[0] == ".log")
	{
		string line = "PRIVMSG " + responseDestination;

		if(words.size() < 2 || (words[1] != "on" && words[1] != "off"))
			line += " :Usage: .log <on|off>\r\n";
		else
		{
			m_parent->enableLogging(words[1] == "on");
			line += string(" :Logging ") + (words[1] == "on" ? "en" : "dis") +
				"abled.\r\n";
		}

		m_socket->send(line.data(), line.size());
	}
	else if(words[0] == ".quit")
	{
		m_daemon->stop();
		string line = "PRIVMSG " + responseDestination + " :Stopping mwcollectd."
			"\r\n";
		m_socket->send(line.data(), line.size());
	}
}

void IrcConnection::splitWords(const char * c, vector<string>& words)
{
	string current;

	words.clear();

	while(* c)
	{
		if(* c != ' ')
			current.push_back(* c);
		else
		{
			words.push_back(current);
			current.erase();
		}

		++c;
	}

	if(!current.empty())
		words.push_back(current);
}

bool IrcConnection::checkCommand(string& user, string& command, string& error)
{
	if(command == ".version")
		return true;

	for(vector<string>::iterator i =
		m_configuration->administrators.begin();
		i != m_configuration->administrators.end(); ++i)
	{
		if(fnmatch(i->c_str(), user.c_str(), FNM_NOESCAPE
			| FNM_PERIOD) == 0)
		{
			return true;
		}
	}

	error = "No access pattern matching your hostmask.";
	return false;
}

void IrcConnection::connectionClosed()
{
	m_daemon->getNameResolvingFacility()->cancelResolutions(this);

	m_parent->childDied(this);
}


void IrcConnection::logMessage(const char * message)
{
	if(m_connected) {
		string line = "PRIVMSG " + m_configuration->channel + " :\x03\x35" + message
			+ "\x03\r\n";
		m_socket->send(line.data(), line.size());
	}
}

