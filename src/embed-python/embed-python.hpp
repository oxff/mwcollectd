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


#ifndef __MWCOLLECTD_EMBEDPYTHON_HPP
#define __MWCOLLECTD_EMBEDPYTHON_HPP

#include <Python.h>

#include <mwcollectd.hpp>
using namespace mwcollectd;

#include <list>
#include <tr1/unordered_map>
using namespace std;
using namespace std::tr1;


class DynamicPythonEndpointFactory;

class EmbedPythonModule : public Module, public EventSubscriber
{
public:
	EmbedPythonModule(Daemon * daemon)
		: m_daemon(daemon)
	{ }
	virtual ~EmbedPythonModule() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "embed-python"; }
	virtual const char * getDescription() { return "Embeds the python"
		" language for service emulation."; }

	virtual void handleEvent(Event * ev);

	static string toString(PyObject * obj);
	void logError();

	enum PythonServerMode
	{
		PYSRVM_DYNAMIC,
		PYSRVM_BIND,
	};

	inline PythonServerMode getServerMode()
	{ return m_serverMode; }

	inline const string& getEnforceAddress()
	{ return m_enforceAddress; }

	inline bool registerStreamProvider(uint16_t port, PyTypeObject * type)
	{
		pair<StreamProviderMap::iterator, bool> result = 
			m_providers.insert(StreamProviderMap::value_type(port, StreamProvider(type)));
		
		return result.second;
	}

	void deregisterStreamProvider(uint16_t port);

protected:
	inline void deregisterFactory(string address, uint16_t port, DynamicPythonEndpointFactory * factory)
	{
		StreamProviderMap::iterator it = m_providers.find(port);
		StreamProvider::ServerMap::iterator jt;

		if(it == m_providers.end())
			return;

		if((jt = it->second.servers.find(address)) == it->second.servers.end())
			return;

		if(jt->second.second != factory)
			return;

		jt->second.first->close();
		it->second.servers.erase(jt);
	}

	friend class DynamicPythonEndpointFactory;

private:
	Daemon * m_daemon;
	string m_modulepath;

	list<PyObject *> m_modules;

	string m_enforceAddress;
	PythonServerMode m_serverMode;

	struct StreamProvider
	{
		StreamProvider(PyTypeObject * t)
		{ type = t; }

		PyTypeObject * type;

		typedef unordered_map<string, pair<NetworkSocket *, DynamicPythonEndpointFactory *> > ServerMap;
		ServerMap servers;
	};

	typedef unordered_map<uint16_t, StreamProvider> StreamProviderMap;
	StreamProviderMap m_providers;
};

extern EmbedPythonModule * g_module;
extern Daemon * g_daemon;


class PythonEndpoint;

typedef struct {
	PyObject_HEAD
	PythonEndpoint * endpoint;

	long sustain, kill;
	Timeout tSustain, tKill;
} mwcollectd_NetworkEndpointTimeouts;

typedef struct {
	PyObject_HEAD
	PythonEndpoint * endpoint;
	mwcollectd_NetworkEndpointTimeouts * timeouts;
} mwcollectd_NetworkEndpoint;


class PythonEndpoint : public NetworkEndpoint, public NameResolver, public TimeoutReceiver
{
public:
	PythonEndpoint(PyObject * endpoint)
		: m_socket(0), m_cachePort(0)
	{ m_pyEndpoint = (mwcollectd_NetworkEndpoint *) endpoint; }
	virtual ~PythonEndpoint();

	virtual void dataRead(const char * buffer, uint32_t dataLength);

	virtual void connectionEstablished(NetworkNode * remoteNode, NetworkNode * localNode);
	virtual void connectionClosed();

	virtual void timeoutFired(Timeout t);

#if 0
	virtual void dataSent(uint32_t length);
#endif

	inline void send(const uint8_t * buffer, uint32_t length)
	{
		m_socket->send((const char *) buffer, length);
		
		m_recorder->appendStreamData(StreamRecorder::DIR_OUTGOING,
			buffer, length);
	}

	inline void close()
	{
		m_socket->close();
	}
				

	inline void setSocket(NetworkSocket * sock)
	{ m_socket = sock; }

	inline void cachePort(uint16_t port)
	{ m_cachePort = port; }

	virtual void nameResolved(string name, list<string> addresses,
                NameResolutionStatus status);

	inline StreamRecorder * getStreamRecorder()
	{ return m_recorder; }

private:
	NetworkSocket * m_socket;
	mwcollectd_NetworkEndpoint * m_pyEndpoint;

	StreamRecorder * m_recorder;

	uint16_t m_cachePort;
};


class PythonEndpointFactory : public NetworkEndpointFactory
{
public:
	PythonEndpointFactory(PyTypeObject * endpointType)
		: m_refCount(1)
	{ m_endpointType = endpointType; }
	virtual ~PythonEndpointFactory() { }

	virtual NetworkEndpoint * createEndpoint(NetworkSocket * clientSocket);
	virtual void destroyEndpoint(NetworkEndpoint * endpoint);

	inline void decref()
	{
		if(!--m_refCount)
			delete this;
	}

	inline size_t refs()
	{ return m_refCount; }

private:
	PyTypeObject * m_endpointType;
	size_t m_refCount;
};

class DynamicPythonEndpointFactory : public PythonEndpointFactory, public TimeoutReceiver
{
public:
	DynamicPythonEndpointFactory(PyTypeObject * type, string address, uint16_t port)
		: PythonEndpointFactory(type)
	{
		m_address = address;
		m_port = port;
	}

	virtual NetworkEndpoint * createEndpoint(NetworkSocket * clientSocket);
	virtual void destroyEndpoint(NetworkEndpoint * endpoint);

	virtual void timeoutFired(Timeout timeout);
	inline void setTimeout(Timeout t)
	{ m_timeout = t; }

protected:
	string m_address;
	uint16_t m_port;
	Timeout m_timeout;
};

PyMODINIT_FUNC PyInit_mwcollectd();



#endif // __MWCOLLECTD_EMBEDPYTHON_HPP
