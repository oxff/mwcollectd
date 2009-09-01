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



static PyObject * mwcollectd_NetworkEndpoint_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	mwcollectd_NetworkEndpoint * self = (mwcollectd_NetworkEndpoint *) type->tp_alloc(type, 0);
	
	if(!self)
		return 0;

	self->endpoint = 0;

	return (PyObject *) self;
}

static void mwcollectd_NetworkEndpoint_dealloc(mwcollectd_NetworkEndpoint * self)
{
	if(self->endpoint)
		delete self->endpoint;

	Py_TYPE((PyObject *) self)->tp_free(self);
}

static PyObject * mwcollectd_NetworkEndpoint_send(PyObject *self, PyObject *args)
{
	const uint8_t * buffer;
	int length;

	if(!PyArg_ParseTuple(args, "y#:NetworkEndpoint.send", &buffer, &length))
		return 0;

	if(!((mwcollectd_NetworkEndpoint *) self)->endpoint)
	{
		PyErr_SetString(PyExc_ValueError, "Endpoint is not initialized (connect it first).");
		return 0;
	}

	((mwcollectd_NetworkEndpoint *) self)->endpoint->send(buffer, length);

	Py_RETURN_NONE;
}


static PyMethodDef mwcollectd_NetworkEndpoint_methods[] = {
	{ "send", mwcollectd_NetworkEndpoint_send, METH_VARARGS,
		"Send a given byte buffer out to the network." },
	{ 0, 0, 0, 0 }
};

static PyTypeObject mwcollectd_NetworkEndpointType = {
	PyObject_HEAD_INIT(NULL)
	"mwcollectd.NetworkEndpoint",
	sizeof(mwcollectd_NetworkEndpoint),
	0,
	(void (*) (PyObject *))mwcollectd_NetworkEndpoint_dealloc,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	"Network endpoint of a connection, receiving and sending data.",
	0, 0, 0, 0, 0, 0,
	mwcollectd_NetworkEndpoint_methods,
	0, 0, 0, 0, 0, 0, 0, 0, 0,
	mwcollectd_NetworkEndpoint_new
};



typedef struct {
	PyObject_HEAD
	PyObject * endpointType;
	PythonEndpointFactory * factory;
	NetworkSocket * server;
} mwcollectd_NetworkServer;

static PyObject * mwcollectd_NetworkServer_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	mwcollectd_NetworkServer * self = (mwcollectd_NetworkServer *) type->tp_alloc(type, 0);
	const char * address;
	uint16_t port;
	uint8_t backlog = 4;
	
	if(!self)
		return 0;

	if(!PyArg_ParseTuple(args, "(sH)O|B", &address, &port, &self->endpointType, &backlog) || !self->endpointType)
		return 0;

	if(!PyType_CheckExact(self->endpointType)
			|| !PyType_IsSubtype((PyTypeObject *) self->endpointType, &mwcollectd_NetworkEndpointType)
			|| !PyCallable_Check(self->endpointType))
	{
		PyErr_Format(PyExc_TypeError, "NetworkServer() argument 1 must be mwcollectd.NetworkEndpoint subclass, not %s",
			EmbedPythonModule::toString((PyObject *) Py_TYPE(self->endpointType)).c_str());

		self->endpointType = 0;
		return 0;
	}

	Py_INCREF(self->endpointType);
	
	if(!(self->factory = new PythonEndpointFactory((PyTypeObject *) self->endpointType)))
	{
		Py_DECREF(self->endpointType);
		return 0;
	}

	NetworkNode localNode = { string(address), port };

	if(!(self->server = g_daemon->getNetworkManager()->serverStream(&localNode, self->factory, backlog)))
	{
		delete self->factory;
		Py_DECREF(self->endpointType);

		PyErr_SetString(PyExc_RuntimeError, "Could not bind socket to specified address, it's either in use or the address string is faulty.");
		return 0;
	}

	return (PyObject *) self;
}

static void mwcollectd_NetworkServer_dealloc(mwcollectd_NetworkServer * self)
{
	if(self->server && !self->server->close(true))
		delete self->server;

	Py_XDECREF(self->endpointType);
	self->factory->decref();

	Py_TYPE((PyObject *) self)->tp_free(self);
}

static PyObject * mwcollectd_NetworkServer_close(mwcollectd_NetworkServer * self, PyObject * args)
{
	if(!self->server->close(true))
	{
		PyErr_SetString(PyExc_RuntimeError, "Could not close server socket.");
		return 0;
	}

	self->server = 0;

	Py_RETURN_NONE;
}


static PyMethodDef mwcollectd_NetworkServer_methods[] = {
	{ "close", (PyObject * (*)(PyObject *, PyObject *)) mwcollectd_NetworkServer_close, METH_NOARGS,
		"Shutdown the network server and release the bound port." },
	{ 0, 0, 0, 0 }
};

static PyTypeObject mwcollectd_NetworkServerType = {
	PyObject_HEAD_INIT(NULL)
	"mwcollectd.NetworkServer",
	sizeof(mwcollectd_NetworkServer),
	0, 
	(void (*)(PyObject *)) mwcollectd_NetworkServer_dealloc,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	Py_TPFLAGS_DEFAULT,
	"Network server serving endpoints to new connections.",
	0, 0, 0, 0, 0, 0,
	mwcollectd_NetworkServer_methods,
	0, 0, 0, 0, 0, 0, 0, 0, 0,
	mwcollectd_NetworkServer_new
};



static PyObject * mwcollectd_log(PyObject *self, PyObject *args)
{
	LogManager::LogLevel level;
	const char * msg;

	if(!PyArg_ParseTuple(args, "is:log", &level, &msg))
		return 0;

	GLOG(level, "%s", msg);

	Py_RETURN_NONE;
}

static PyObject * mwcollectd_connect(PyObject *self, PyObject *args)
{
	const char * address;
	uint16_t port;
	mwcollectd_NetworkEndpoint * connection;

	if(!PyArg_ParseTuple(args, "(sH)O!:connectStream", &address, &port, &mwcollectd_NetworkEndpointType, &connection) || !connection)
		return 0;

	NetworkNode remoteNode = { string(address), port };

	if(connection->endpoint)
	{
		PyErr_SetString(PyExc_ValueError, "Endpoint is already initialized, create a new one.");
		return 0;
	}

	if(!port)
	{
		PyErr_SetString(PyExc_ValueError, "Port 0 is reserved internally (and usually not sane).");
		return 0;
	}

	connection->endpoint = new PythonEndpoint((PyObject *) connection);
	NetworkSocket * socket = g_daemon->getNetworkManager()->connectStream(&remoteNode, connection->endpoint);

	if(socket)
		connection->endpoint->setSocket(socket);
	else
	{
		connection->endpoint->cachePort(port);
		g_daemon->getNameResolvingFacility()->resolveName(string(address), connection->endpoint);
	}

	Py_INCREF((PyObject *) connection);

	Py_RETURN_NONE;
}


static PyMethodDef mwcollectdmethods[] = {
	{ "log", mwcollectd_log, METH_VARARGS,
		"Log given string with given log level." },
	{ "connectStream", mwcollectd_connect, METH_VARARGS,
		"Connect to a given IP, port via TCP." },
	{ 0, 0, 0, 0 }
};

static PyModuleDef mwcollectdmodule = {
	PyModuleDef_HEAD_INIT,
	"mwcollectd",
	"Interface to mwcollectd for extension modules.",
	-1,
	mwcollectdmethods,
	NULL, NULL, NULL, NULL
};


PyMODINIT_FUNC PyInit_mwcollectd() 
{
	PyObject * module;

	if(PyType_Ready(&mwcollectd_NetworkEndpointType) < 0 || PyType_Ready(&mwcollectd_NetworkServerType) < 0)
		return 0;

	if(!(module = PyModule_Create(&mwcollectdmodule)))
		return 0;

	PyModule_AddIntConstant(module, "L_EVENT", (long) LogManager::LL_EVENT);
	PyModule_AddIntConstant(module, "L_SPAM", (long) L_SPAM);
	PyModule_AddIntConstant(module, "L_INFO", (long) L_INFO);
	PyModule_AddIntConstant(module, "L_CRIT", (long) L_CRIT);

	PyModule_AddStringConstant(module, "version", g_daemon->getVersion());

	Py_INCREF(&mwcollectd_NetworkEndpointType);
	PyModule_AddObject(module, "NetworkEndpoint", (PyObject *) &mwcollectd_NetworkEndpointType);
	
	Py_INCREF(&mwcollectd_NetworkServerType);
	PyModule_AddObject(module, "NetworkServer", (PyObject *) &mwcollectd_NetworkServerType);

	return module;
}



