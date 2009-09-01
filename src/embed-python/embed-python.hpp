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
using namespace std;


class EmbedPythonModule : public Module
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


	static string toString(PyObject * obj);
	void logError();

private:
	Daemon * m_daemon;
	string m_modulepath;

	list<PyObject *> m_modules;
};

extern EmbedPythonModule * g_module;
extern Daemon * g_daemon;


class PythonEndpoint : public NetworkEndpoint, public NameResolver
{
public:
	PythonEndpoint(PyObject * endpoint)
		: m_socket(0), m_cachePort(0)
	{ m_pyEndpoint = endpoint; }
	virtual ~PythonEndpoint();

	virtual void dataRead(const char * buffer, uint32_t dataLength);

	virtual void connectionEstablished(NetworkNode * remoteNode, NetworkNode * localNode);
	virtual void connectionClosed();

#if 0
	virtual void dataSent(uint32_t length);
#endif

	inline void send(const uint8_t * buffer, uint32_t length)
	{
		m_socket->send((const char *) buffer, length);
		
		m_recorder->appendStreamData(StreamRecorder::DIR_OUTGOING,
			buffer, length);
	}
				

	inline void setSocket(NetworkSocket * sock)
	{ m_socket = sock; }

	inline void cachePort(uint16_t port)
	{ m_cachePort = port; }

	virtual void nameResolved(string name, list<string> addresses,
                NameResolutionStatus status);

private:
	NetworkSocket * m_socket;
	PyObject * m_pyEndpoint;

	StreamRecorder * m_recorder;

	uint16_t m_cachePort;
};


typedef struct {
	PyObject_HEAD
	PythonEndpoint * endpoint;
} mwcollectd_NetworkEndpoint;


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

private:
	PyTypeObject * m_endpointType;
	size_t m_refCount;
};


PyMODINIT_FUNC PyInit_mwcollectd();



#endif // __MWCOLLECTD_EMBEDPYTHON_HPP
