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


MirrorEndpoint::~MirrorEndpoint()
{
	if(m_StreamRecorder)
		m_StreamRecorder->release();
}

void MirrorEndpoint::connectionEstablished(NetworkNode * remoteNode,
	NetworkNode * localNode)
{
	NetworkNode remote = { remoteNode->name, localNode->port };

	m_StreamRecorder = new StreamRecorder(remoteNode, localNode);

	m_idleTimeout = g_daemon->getTimeoutManager()->scheduleTimeout(15, this);

	if(remoteNode->name == "127.0.0.1")
	{
		m_reverseSocket = 0;
		return;
	}

	m_reverseTimeout = g_daemon->getTimeoutManager()->scheduleTimeout(5, this);

	if(!(m_reverseSocket = g_daemon->getNetworkManager()->connectStream(
		&remote, &m_reverseEndpoint)))
	{
		GLOG(L_INFO, "Could not reverse connection.");
	}
	else
		GLOG(L_SPAM, "Mirror connection to %s:%hu initiating...",
			remoteNode->name.c_str(), localNode->port);
}

void MirrorEndpoint::connectionClosed()
{
	m_socket = 0;
	
	{
		Event ev = Event("stream.finished");

		ev["recorder"] = (void *) m_StreamRecorder;

		g_daemon->getEventManager()->fireEvent(&ev);
	}

	closeEndpoint();
}

void MirrorEndpoint::dataRead(const char * buffer, uint32_t dataLength)
{
	if(m_reverseSocket)
		m_reverseSocket->send(buffer, dataLength);

	g_daemon->getTimeoutManager()->dropTimeout(m_idleTimeout);
	m_idleTimeout = g_daemon->getTimeoutManager()->scheduleTimeout(15, this);

	m_StreamRecorder->appendStreamData(m_StreamRecorder->DIR_INCOMING,
		(const uint8_t *) buffer, dataLength);
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
	
	if(m_parent->m_reverseTimeout != TIMEOUT_EMPTY)
	{
		g_daemon->getTimeoutManager()->dropTimeout(m_parent->m_reverseTimeout);
		m_parent->m_reverseTimeout = TIMEOUT_EMPTY;
	}

	if(m_parent->m_socket)
	{
		m_parent->m_socket->send("\r\n", 2);
		m_parent->m_retardTimeout = g_daemon->getTimeoutManager()
			->scheduleTimeout(3, m_parent);
	}

	GLOG(L_SPAM, "Reverse connection closed, falling back to retard mode...");
}

void MirrorEndpoint::ReverseEndpoint::dataRead(const char * buffer, uint32_t dataLength)
{
	m_parent->m_socket->send(buffer, dataLength);

	m_parent->m_StreamRecorder->appendStreamData(m_parent->m_StreamRecorder->
		DIR_OUTGOING, (const uint8_t *) buffer, dataLength);
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
	if(m_reverseSocket)
	{
		m_reverseSocket->close(true);
		m_reverseSocket = 0;
	}

	g_daemon->getTimeoutManager()->dropReceiver(this);
	m_reverseTimeout = TIMEOUT_EMPTY;

	if(m_socket)
		m_socket->close(true);
}
