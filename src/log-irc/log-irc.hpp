/*
 *				    _ _           _      _ 
 *	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
 *	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
 *	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
 *	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
 *
 *
 * 	Copyright 2009 Georg Wicherski, Kaspersky Labs GmbH
 *
 *
 *	This file is part of mwcollectd.
 *
 *	mwcollectd is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU Lesser General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	mwcollectd is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU Lesser General Public License for more details.
 *
 *	You should have received a copy of the GNU Lesser General Public License
 *	along with mwcollectd. If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef __MWCOLLECTD_LOGIRC_HPP
#define __MWCOLLECTD_LOGIRC_HPP

#include <mwcollectd.hpp>
using namespace mwcollectd;

#include <vector>
#include <list>
#include <string>
using namespace std;

struct IrcConfiguration
{
	string password;
	string nickname, ident, realname;
	string channel, key;

	vector<string> administrators;
};


class IrcConnection;

class IrcInterfaceModule : public Module, public NameResolver, public
	LogFacility
{
public:
	IrcInterfaceModule(Daemon * daemon);
	virtual ~IrcInterfaceModule() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "log-irc"; }
	virtual const char * getDescription() { return "Control your mwcollectd "
		"instance over a (preferably trusted) IRC network."; }
	virtual const char * getTarget();
	virtual void logMessage(const char * renderedMessage);

	virtual void nameResolved(string name, list<string> addresses,
		NameResolutionStatus status);

	void childDied(IrcConnection * child);
	void enableLogging(bool enable);

private:
	Daemon * m_daemon;
	IrcConnection * m_connection;
	IrcConfiguration m_configuration;
	NetworkNode m_remoteNode;
	bool m_loggingEnabled;
	
	bool m_unloading;
};

class IrcConnection : public NetworkEndpoint, public NameResolver
{
public:
	IrcConnection(Daemon * daemon, IrcInterfaceModule * parent,
		IrcConfiguration * config);
	~IrcConnection() { }

	virtual void dataRead(const char * buffer, uint32_t dataLength);
	
	virtual void connectionEstablished(NetworkNode * remoteNode,
		NetworkNode * localNode);
	virtual void connectionClosed();

	bool quit();

	void logMessage(const char * msg);

	virtual void nameResolved(string name, list<string> addresses,
		NameResolutionStatus status);
		
	inline void setSocket(NetworkSocket * socket) { m_socket = socket; }

protected:
	void parseLine(string line);
	void splitWords(const char * c, vector<string>& words);
	void parseCommand(string& from, string& to, vector<string>& words);
	bool checkCommand(string& user, string& command, string& error);

private:
	bool m_connected;
	IrcInterfaceModule * m_parent;
	IrcConfiguration * m_configuration;
	NetworkSocket * m_socket;
	Daemon * m_daemon;

	string m_buffer;
	bool m_joined;
};


#endif // __MWCOLLECTD_LOGIRC_HPP
