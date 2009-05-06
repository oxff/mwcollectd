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


#ifndef __MWCOLLECTD_DYNSERVMIRROR_HPP
#define __MWCOLLECTD_DYNSERVMIRROR_HPP

#include <mwcollectd.hpp>
using namespace mwcollectd;

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <tr1/unordered_map>
#include <set>
#include <list>
using namespace std;
using namespace std::tr1;



class MirrorEndpoint : public NetworkEndpoint, public TimeoutReceiver
{
public:
	MirrorEndpoint(NetworkSocket * socket)
		: m_reverseEndpoint(this)
	{ m_socket = socket; m_StreamRecorder = 0; }

	virtual ~MirrorEndpoint();

	virtual void connectionEstablished(NetworkNode * remoteNode,
		NetworkNode * localNode);
	virtual void connectionClosed();
	virtual void dataRead(const char * buffer, uint32_t dataLength);

	virtual void timeoutFired(Timeout timeout);

	void closeEndpoint();

private:
	class ReverseEndpoint : public NetworkEndpoint
	{
	public:
		ReverseEndpoint(MirrorEndpoint * parent)
		{ m_parent = parent; }

		virtual void connectionEstablished(NetworkNode * remoteNode,
			NetworkNode * localNode);
		virtual void connectionClosed();
		virtual void dataRead(const char * buffer, uint32_t dataLength);

	private:
		MirrorEndpoint * m_parent;
	} m_reverseEndpoint;

	NetworkSocket * m_socket, * m_reverseSocket;

	Timeout m_idleTimeout, m_reverseTimeout, m_retardTimeout;
	StreamRecorder * m_StreamRecorder;
};


class DynamicServerMirror;

class MirrorServer : public NetworkEndpointFactory, public TimeoutReceiver
{
public:
	MirrorServer(DynamicServerMirror * parent, uint16_t port, size_t timeout);

	virtual NetworkEndpoint * createEndpoint(NetworkSocket * clientSocket);
	virtual void destroyEndpoint(NetworkEndpoint * endpoint);

	virtual void timeoutFired(Timeout timeout);

	void closeServer();

	inline void setSocket(NetworkSocket * socket)
	{ m_socket = socket; }

private:
	list<MirrorEndpoint *> m_endpoints;
	DynamicServerMirror * m_parent;

	size_t m_maxIdleTime;
	Timeout m_timeout;
	uint16_t m_port;

	NetworkSocket * m_socket;
};

class DynamicServerMirror : public Module, public EventSubscriber
{
public:
	DynamicServerMirror(Daemon * daemon);
	virtual ~DynamicServerMirror() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "dynserv-mirror"; }
	virtual const char * getDescription() { return "Open TCP servers"
		" for dynamic server requests and mirror back traffic to the"
		" attacker."; }

	virtual void handleEvent(Event * event);

protected:
	bool setRanges(const char * range);
	bool mirrorPort(uint16_t port);

	void removeServer(uint16_t port, MirrorServer * server);

	friend class MirrorServer;

private:
	bool addRange(uint16_t port, uint16_t length);

	typedef unordered_map<uint16_t, MirrorServer *> ServerMap;
	ServerMap m_servers;

	Daemon * m_daemon;

	struct PortRange
	{
		uint16_t port;
		uint16_t length;

		bool operator()(PortRange a, PortRange b)
		{ return a.port + a.length < b.port; }
	};

	typedef set<PortRange, PortRange> PortSet;
	PortSet m_ports;
};

extern Daemon * g_daemon;


#endif // __MWCOLLECTD_DYNSERVMIRROR_HPP
