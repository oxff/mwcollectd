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

#include "dynserv-mirror.hpp"


Daemon * g_daemon;

DynamicServerMirror::DynamicServerMirror(Daemon * daemon)
{
	m_daemon = ::g_daemon = daemon;
}

bool DynamicServerMirror::start(Configuration * moduleConfiguration)
{
	if(!moduleConfiguration)
		return false;

	if(!setRanges(moduleConfiguration->getString(":port-range", "0-65535")))
		return false;

	m_enableMirroring = (bool) moduleConfiguration->getInteger(":mirror", 1);

	if(!m_daemon->getEventManager()->subscribeEventMask("stream.request", this))
	{
		LOG(L_CRIT, "%s could not subscribe to `stream.request'!", getName());
		return false;
	}

	return true;
}

bool DynamicServerMirror::stop()
{
	m_daemon->getEventManager()->unsubscribeAll(this);

	for(ServerMap::iterator it = m_servers.begin(); it != m_servers.end(); ++it)
		delete it->second;

	m_servers.clear();

	return true;
}

bool DynamicServerMirror::setRanges(const char * range)
{
	const char * walk;
	uint16_t port = 0, port2 = 0;
	enum
	{
		S_PARSENUM,
		S_PARSENUM2,
	} state;

	for(walk = range, state = S_PARSENUM;; ++walk)
	{
		switch(state)
		{
		case S_PARSENUM:
			if(* walk >= '0' && * walk <= '9')
				port = port * 10 + (* walk  - '0');
			else if(* walk == '-')
				state = S_PARSENUM2;
			else if(* walk == ',' || ! * walk)
			{
				if(!addRange(port, 0))
					return false;

				port = port2 = 0;
			}
			else
			{
				LOG(L_CRIT, "Unexpected literal '%c' in port range at "
					"offset %u!", * walk, walk - range);
				return false;
			}

			break;

		case S_PARSENUM2:
			if(* walk >= '0' && * walk <= '9')
				port2 = port2 * 10 + (* walk  - '0');
			else if(* walk == ',' || ! * walk)
			{
				if(port2 < port)
				{
					LOG(L_CRIT, "Inverted range %u <- %u at offset"
						" %u!", port, port2, walk - range);
					return false;
				}

				if(!addRange(port, port2 - port))
					return false;

				port = port2 = 0;

				state = S_PARSENUM;
			}
			else
			{
				LOG(L_CRIT, "Unexpected literal '%c' in port range at "
					"offset %u!", * walk, walk - range);
				return false;
			}
		}

		if(! * walk)
			break;
	}

	return true;
}

bool DynamicServerMirror::addRange(uint16_t port, uint16_t length)
{
	PortRange range = { port, length };
	PortSet::iterator it = m_ports.lower_bound(range);

	if(it != m_ports.end() && it->port <= port + length)
	{
		LOG(L_CRIT, "Range %u -> %u intersects with %u -> %u.",
			port, port + length, it->port, it->port + it->length);
		return false;
	}

	m_ports.insert(range);
	return true;
}

bool DynamicServerMirror::mirrorPort(uint16_t port)
{
	PortRange range = { port, 0 };
	PortSet::iterator it = m_ports.lower_bound(range);

	if(port >= it->port && port <= it->port + it->length)
		return true;

	return false;
}

void DynamicServerMirror::handleEvent(Event * event)
{
	ASSERT(event->getName() == "stream.request");

	if((* event)["done"].getIntegerValue())
		return;

	uint16_t port = (* event)["port"].getIntegerValue();

	if(m_servers.find(Server(* (* event)["address"], port)) != m_servers.end())
		return;

	if(!mirrorPort(port))
	{
		LOG(L_SPAM, "Not starting mirror server on %s:%u due to port policy.",
			(* (* event)["address"]).c_str(), port);
		return;
	}

	LOG(L_SPAM, "Spawning new mirror server on %s:%u.",
		(* (* event)["address"]).c_str(), port);

	NetworkNode local;

	local.name = * (* event)["address"];
	local.port = port;

	MirrorServer * server = new MirrorServer(this, local.name, port, 30);
	NetworkSocket * socket;

	if(!(socket = m_daemon->getNetworkManager()->serverStream(&local, server, 4)))
	{
		delete server;
		LOG(L_INFO, "Could not spawn mirror server on :%u.", port);
	}
	else
	{
		m_servers[Server(local.name, port)] = server;
		server->setSocket(socket);

		(* event)["done"] = 1;
	}	
}

void DynamicServerMirror::removeServer(const Server& server, MirrorServer * s)
{
	ServerMap::iterator it = m_servers.find(server);

	if(it->second == s)
		m_servers.erase(it);
}


EXPORT_LIBNETWORKD_MODULE(DynamicServerMirror, Daemon *);

