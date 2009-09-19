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

#include "embed-python.hpp"



PythonEndpoint::~PythonEndpoint()
{
	if(m_cachePort)
		g_daemon->getNameResolvingFacility()->cancelResolutions(this);
}

void PythonEndpoint::dataRead(const char * buf, uint32_t length)
{
	m_recorder->appendStreamData(StreamRecorder::DIR_INCOMING,
		(const uint8_t *) buf, length);

	if(((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->sustain >= 0)
	{
		if(((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tSustain != TIMEOUT_EMPTY)
			g_daemon->getTimeoutManager()->dropTimeout(((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tSustain);

		((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tSustain = g_daemon->getTimeoutManager()->scheduleTimeout(
			((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->sustain, this);
	}

	PyObject * fn = PyObject_GetAttrString(m_pyEndpoint, "dataRead");

	if(!fn || !PyCallable_Check(fn))
	{
		GLOG(L_CRIT, "%s has no callable attribute 'dataRead'!",
			EmbedPythonModule::toString(m_pyEndpoint).c_str());
		PyErr_Clear();
		return;
	}
	
	PyObject * args = Py_BuildValue("(y#)", buf, length);
	PyObject * res = PyObject_CallObject(fn, args);
	Py_DECREF(fn);

	if(!res)
	{
		GLOG(L_CRIT, "Calling attribute 'dataRead' of %s failed:", 
			EmbedPythonModule::toString(m_pyEndpoint).c_str());

		g_module->logError();
		PyErr_Clear();

		Py_XDECREF(args);
		return;
	}
	
	Py_DECREF(res);
	Py_XDECREF(args);
}

void PythonEndpoint::connectionEstablished(NetworkNode * remote, NetworkNode * local)
{
	PyObject * fn = PyObject_GetAttrString(m_pyEndpoint, "connectionEstablished");

	m_recorder = new StreamRecorder(remote, local);

	if(!fn || !PyCallable_Check(fn))
	{
		GLOG(L_CRIT, "%s has no callable attribute 'connectionEstablished'!",
			EmbedPythonModule::toString(m_pyEndpoint).c_str());

		PyErr_Clear();
		return;
	}

	PyObject * res = PyObject_CallObject(fn, 0);
	Py_DECREF(fn);

	if(!res)
	{
		GLOG(L_CRIT, "Calling attribute 'connectionEstablished' of %s failed:", 
			EmbedPythonModule::toString(m_pyEndpoint).c_str());

		g_module->logError();
		PyErr_Clear();

		return;
	}
	
	Py_DECREF(res);
}

void PythonEndpoint::connectionClosed()
{
	{
		Event ev = Event("stream.finished");

		ev["recorder"] = (void *) m_recorder;
		g_daemon->getEventManager()->fireEvent(&ev);
	}

	{
		PyObject * fn = PyObject_GetAttrString(m_pyEndpoint, "connectionClosed");

		if(!fn || !PyCallable_Check(fn))
		{
			GLOG(L_SPAM, "%s has no callable attribute 'connectionClosed'!",
				EmbedPythonModule::toString(m_pyEndpoint).c_str());

			PyErr_Clear();
			Py_DECREF(m_pyEndpoint);

			return;
		}

		PyObject * res = PyObject_CallObject(fn, 0);
		Py_DECREF(fn);

		if(!res)
		{
			GLOG(L_CRIT, "Calling attribute 'connectionClosed' of %s failed:", 
				EmbedPythonModule::toString(m_pyEndpoint).c_str());

			g_module->logError();
			PyErr_Clear();

			Py_DECREF(fn);
			Py_DECREF(m_pyEndpoint);

			return;
		}

		Py_DECREF(res);

		Py_DECREF(m_pyEndpoint);
	}
}

void PythonEndpoint::nameResolved(string name, list<string> addresses,
	NameResolutionStatus status)
{
	if(status != NRS_OK)
		return connectionLost();

	NetworkNode remoteNode = { addresses.front(), m_cachePort };

	if(!(m_socket = g_daemon->getNetworkManager()->connectStream(&remoteNode, this)))
		return connectionLost();

	m_cachePort = 0;
}

void PythonEndpoint::timeoutFired(Timeout t)
{
	if(t == ((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tSustain)
	{
		((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->sustain = -1;
		((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tSustain = TIMEOUT_EMPTY;

		m_socket->close(true);
	}
	else if(t == ((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tKill)
	{
		GLOG(L_CRIT, "%s: %p, %p, %p", __PRETTY_FUNCTION__, m_socket, t,
				((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tKill);

		((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->kill = -1;
		((mwcollectd_NetworkEndpoint *) m_pyEndpoint)->timeouts->tKill = TIMEOUT_EMPTY;

		m_socket->close(true);
	}
}



NetworkEndpoint * PythonEndpointFactory::createEndpoint(NetworkSocket * clientSocket)
{
	PyObject * args = PyTuple_New(0);
	mwcollectd_NetworkEndpoint * endpointObj = (mwcollectd_NetworkEndpoint *) PyObject_Call((PyObject *) m_endpointType, args, Py_None);
	Py_XDECREF(args);

	if(!endpointObj)
	{
		GLOG(L_CRIT, "Creation of endpoint for %s failed:", EmbedPythonModule::toString((PyObject *) m_endpointType).c_str());
		g_module->logError();

		return 0;
	}
	
	++ m_refCount;

	endpointObj->endpoint = new PythonEndpoint((PyObject *) endpointObj);
	endpointObj->endpoint->setSocket(clientSocket);

	endpointObj->timeouts->endpoint = endpointObj->endpoint;

	return endpointObj->endpoint;
}

void PythonEndpointFactory::destroyEndpoint(NetworkEndpoint * endpoint)
{
	// Endpoints destroy themselves upon connectionClose() / connectionLost()
	
	decref();
}


void DynamicPythonEndpointFactory::timeoutFired(Timeout timeout)
{
	if(timeout != m_timeout)
		return;

	m_timeout = TIMEOUT_EMPTY;

	if(refs() == 1)
		g_module->deregisterFactory(m_address, m_port, this);

	decref();
}

NetworkEndpoint * DynamicPythonEndpointFactory::createEndpoint(NetworkSocket * clientSocket)
{
	if(m_timeout != TIMEOUT_EMPTY)
	{
		g_daemon->getTimeoutManager()->dropTimeout(m_timeout);
		m_timeout = g_daemon->getTimeoutManager()->scheduleTimeout(30, this);
	}
	
	return PythonEndpointFactory::createEndpoint(clientSocket);
}
void DynamicPythonEndpointFactory::destroyEndpoint(NetworkEndpoint * endpoint)
{
	if(refs() == 1)
	{
		g_module->deregisterFactory(m_address, m_port, this);

		g_daemon->getTimeoutManager()->dropTimeout(m_timeout);
		m_timeout = TIMEOUT_EMPTY;
	}

	return PythonEndpointFactory::destroyEndpoint(endpoint);
}

