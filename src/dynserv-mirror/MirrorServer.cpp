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

MirrorServer::MirrorServer(DynamicServerMirror * parent, const string& address, uint16_t port, size_t timeout)
{
	m_parent = parent;
	m_maxIdleTime = timeout;
	m_timeout = g_daemon->getTimeoutManager()->scheduleTimeout(timeout, this);
	m_port = port;
	m_address = address;
}

MirrorServer::~MirrorServer()
{
	if(m_timeout != TIMEOUT_EMPTY)
		g_daemon->getTimeoutManager()->dropTimeout(m_timeout);
}

NetworkEndpoint * MirrorServer::createEndpoint(NetworkSocket * clientSocket)
{
	MirrorEndpoint * endpoint = new MirrorEndpoint(clientSocket, m_parent->enableMirroring());
	m_endpoints.push_back(endpoint);

	g_daemon->getTimeoutManager()->dropTimeout(m_timeout);
	m_timeout = g_daemon->getTimeoutManager()->scheduleTimeout(m_maxIdleTime, this);

	return endpoint;
}

void MirrorServer::destroyEndpoint(NetworkEndpoint * endpoint)
{
	m_endpoints.remove((MirrorEndpoint *) endpoint);
	delete (MirrorEndpoint *) endpoint;
}

void MirrorServer::timeoutFired(Timeout timeout)
{
	ASSERT(timeout == m_timeout);

	if(!m_endpoints.empty())
	{
		GLOG(L_SPAM, "Mirror server for %s:%u did not serve a connection within %u "
			"seconds, but still has children...", m_address.c_str(), m_port, m_maxIdleTime);

		m_timeout = g_daemon->getTimeoutManager()->scheduleTimeout(m_maxIdleTime >> 1, this);
		return;
	}

	GLOG(L_SPAM, "Mirror server for %s:%u did not serve a connection within %u "
		"seconds, closing.", m_address.c_str(), m_port, m_maxIdleTime);

	m_parent->removeServer(DynamicServerMirror::Server(m_address, m_port), this);

	m_timeout = TIMEOUT_EMPTY;
	closeServer();
}

void MirrorServer::closeServer()
{
	m_socket->close(true);
	delete this;
}
