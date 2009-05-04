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

#include <sstream>


void MirrorEndpoint::connectionEstablished(NetworkNode * remoteNode,
	NetworkNode * localNode)
{
	NetworkNode remote = { remoteNode->name, localNode->port };

	if(!(m_reverseSocket = g_daemon->getNetworkManager()->connectStream(
		&remote, &m_reverseEndpoint)))
	{
		GLOG(L_INFO, "Could not reverse connection!");
	}
	else
		GLOG(L_INFO, "Mirror connection to %s:%hu initiating...",
			remoteNode->name.c_str(), localNode->port);

	m_idleTimeout = g_daemon->getTimeoutManager()->scheduleTimeout(15, this);
	m_reverseTimeout = g_daemon->getTimeoutManager()->scheduleTimeout(5, this);
}

void MirrorEndpoint::connectionClosed()
{
	if(m_reverseSocket)
		m_reverseSocket->close(true);

	m_socket = 0;
	closeEndpoint();
}

void MirrorEndpoint::dataRead(const char * buffer, uint32_t dataLength)
{
	if(m_reverseSocket)
		m_reverseSocket->send(buffer, dataLength);

	g_daemon->getTimeoutManager()->dropTimeout(m_idleTimeout);
	m_idleTimeout = g_daemon->getTimeoutManager()->scheduleTimeout(15, this);

	{
		char dump[dataLength * 3 + 1];
		register char * p = dump;

		for(size_t k = 0; k < dataLength; ++k)
		{
			sprintf(p, "%02hx ", buffer[k] & 0xff);
			p += 3;
		}

		* p = 0;

		GLOG(L_SPAM, "DATA: %s", dump);
	}
}

void MirrorEndpoint::ReverseEndpoint::connectionEstablished(NetworkNode * remoteNode,
	NetworkNode * localNode)
{
	g_daemon->getTimeoutManager()->dropTimeout(m_parent->m_reverseTimeout);
	m_parent->m_reverseTimeout = TIMEOUT_EMPTY;
}

void MirrorEndpoint::ReverseEndpoint::connectionClosed()
{
	m_parent->m_reverseSocket = 0;
	g_daemon->getTimeoutManager()->dropTimeout(m_parent->m_reverseTimeout);
	m_parent->m_reverseTimeout = TIMEOUT_EMPTY;
	
	m_parent->m_socket->send("\r\n", 2);
	m_parent->m_retardTimeout = g_daemon->getTimeoutManager()
		->scheduleTimeout(3, m_parent);
}

void MirrorEndpoint::ReverseEndpoint::dataRead(const char * buffer, uint32_t dataLength)
{
	m_parent->m_socket->send(buffer, dataLength);

	char dump[dataLength * 3 + 1];
	register char * p = dump;

	for(size_t k = 0; k < dataLength; ++k)
	{
		sprintf(p, "%02hx ", buffer[k] & 0xff);
		p += 3;
	}

	* p = 0;

	GLOG(L_SPAM, "RDATA: %s", dump);
}

void MirrorEndpoint::timeoutFired(Timeout timeout)
{
	if(timeout == m_idleTimeout)
	{
		GLOG(L_INFO, "No data on mirror connection, dropping.");
		closeEndpoint();
	}
	else if(timeout == m_reverseTimeout)
	{
		GLOG(L_INFO, "Reverse connection timed out, falling back...");

		m_reverseSocket->close(true);
		m_reverseSocket = 0;

		m_socket->send("\r\n", 2);
		m_retardTimeout = g_daemon->getTimeoutManager()
			->scheduleTimeout(3, this);
	}
	else if(timeout == m_retardTimeout)
	{
		m_socket->send("\r\n", 2);
		m_retardTimeout = g_daemon->getTimeoutManager()
			->scheduleTimeout(3, this);
	}
}

void MirrorEndpoint::closeEndpoint()
{
	g_daemon->getTimeoutManager()->dropReceiver(this);

	if(m_reverseSocket)
	{
		m_reverseSocket->close(true);
		m_reverseSocket = 0;
	}

	if(m_socket)
		m_socket->close(true);
}
