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
#include <structmember.h>




void mwcollectd_NetworkEndpointTimeouts_dealloc(mwcollectd_NetworkEndpointTimeouts * self)
{
	Py_TYPE((PyObject *) self)->tp_free(self);
}

static PyObject * mwcollectd_NetworkEndpointTimeouts_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PyErr_SetString(PyExc_RuntimeError, "This type may not be directly instantiated from python.");
	return 0;
}


#define SETATTR_CHECK_INIT() \
	if(!self->endpoint) \
	{ \
		PyErr_SetString(PyExc_AttributeError, "Network endpoint timeout set before connection was established."); \
		return -1; \
	}

int mwcollectd_NetworkEndpointTimeouts_setattr(mwcollectd_NetworkEndpointTimeouts * self, char * name, PyObject * value)
{
	PyObject * attrname = PyUnicode_FromString(name);
	int result =  PyObject_GenericSetAttr((PyObject *) self, attrname, value);
	Py_XDECREF(attrname);

	if(result < 0)
		return result;

	if(!strcmp(name, "sustain"))
	{
		SETATTR_CHECK_INIT();

		if(self->tSustain != TIMEOUT_EMPTY)
			g_daemon->getTimeoutManager()->dropTimeout(self->tSustain);

		if(self->sustain > 0)
			self->tSustain = g_daemon->getTimeoutManager()->scheduleTimeout(self->sustain, self->endpoint);
	}

	if(!strcmp(name, "kill"))
	{
		SETATTR_CHECK_INIT();

		if(self->tKill != TIMEOUT_EMPTY)
			g_daemon->getTimeoutManager()->dropTimeout(self->tKill);

		if(self->kill > 0)
			self->tKill = g_daemon->getTimeoutManager()->scheduleTimeout(self->kill, self->endpoint);
	}

	return result;
}

#undef SETATTR_CHECK_INIT



static PyMemberDef mwcollectd_NetworkEndpointTimeouts_members[] = {
	{ (char *) "sustain", T_LONG, offsetof(mwcollectd_NetworkEndpointTimeouts, sustain), 0,
		(char *) "Timeout in seconds before an idle connection is closed (sending does not count as activity)." },
	{ (char *) "kill", T_LONG, offsetof(mwcollectd_NetworkEndpointTimeouts, kill), 0,
		(char *) "Timeout in seconds after which this connection is killed effectively." },
	{ 0, 0, 0, 0, 0 }
};

static PyTypeObject mwcollectd_NetworkEndpointTimeoutsType = {
	PyObject_HEAD_INIT(NULL)
	"mwcollectd.NetworkEndpointTimeouts",
	sizeof(mwcollectd_NetworkEndpointTimeouts),
	0,
	(void (*) (PyObject *)) mwcollectd_NetworkEndpointTimeouts_dealloc,
	0, 0,
	(int (*) (PyObject *, char *, PyObject *)) mwcollectd_NetworkEndpointTimeouts_setattr, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	Py_TPFLAGS_DEFAULT,
	"Network timeouts for an endpoint.",
	0, 0, 0, 0, 0, 0,
	0, // methods
	mwcollectd_NetworkEndpointTimeouts_members,
	0, 0, 0, 0, 0, 0, 0, 0,
	mwcollectd_NetworkEndpointTimeouts_new
};



static PyObject * mwcollectd_NetworkEndpoint_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	mwcollectd_NetworkEndpoint * self = (mwcollectd_NetworkEndpoint *) type->tp_alloc(type, 0);
	
	if(!self)
		return 0;

	self->endpoint = 0;
	self->timeouts = PyObject_New(mwcollectd_NetworkEndpointTimeouts, &mwcollectd_NetworkEndpointTimeoutsType);
	self->timeouts->endpoint =  0;

	self->timeouts->sustain = 0;
	self->timeouts->tSustain = TIMEOUT_EMPTY;
	self->timeouts->kill = 0;
	self->timeouts->tKill = TIMEOUT_EMPTY;

	return (PyObject *) self;
}

static void mwcollectd_NetworkEndpoint_dealloc(mwcollectd_NetworkEndpoint * self)
{
	if(self->endpoint)
		delete self->endpoint;

	Py_TYPE((PyObject *) self->timeouts)->tp_free(self->timeouts);

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

static PyObject * mwcollectd_NetworkEndpoint_close(PyObject *self, PyObject *args)
{
	if(!((mwcollectd_NetworkEndpoint *) self)->endpoint)
	{
		PyErr_SetString(PyExc_ValueError, "Endpoint is not initialized (connect it first).");
		return 0;
	}

	((mwcollectd_NetworkEndpoint *) self)->endpoint->close();

	Py_RETURN_NONE;
}

static PyObject * mwcollectd_NetworkEndpoint_getRecorder(PyObject *self, PyObject *args)
{
	return PyCObject_FromVoidPtr(((mwcollectd_NetworkEndpoint *) self)->endpoint->getStreamRecorder(), 0);
}


static PyMethodDef mwcollectd_NetworkEndpoint_methods[] = {
	{ "close", mwcollectd_NetworkEndpoint_close, METH_NOARGS,
		"Close the current connection." },
	{ "send", mwcollectd_NetworkEndpoint_send, METH_VARARGS,
		"Send a given byte buffer out to the network." },
	{ "getRecorder", mwcollectd_NetworkEndpoint_getRecorder, METH_NOARGS,
		"Obtain the opaque descriptor of the recorder associated with this endpoint." },
	{ 0, 0, 0, 0 }
};

static PyMemberDef mwcollectd_NetworkEndpoint_members[] = {
	{ (char *) "timeouts", T_OBJECT_EX, offsetof(mwcollectd_NetworkEndpoint, timeouts), READONLY, (char *) "Network timeouts." },
	{ 0, 0, 0, 0, 0 }
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
	mwcollectd_NetworkEndpoint_members,
	0, 0, 0, 0, 0, 0, 0, 0,
	mwcollectd_NetworkEndpoint_new
};



typedef struct {
	PyObject_HEAD
	PyObject * endpointType;
	EmbedPythonModule::PythonServerMode mode;

	union
	{
		struct {
			PythonEndpointFactory * factory;
			NetworkSocket * server;
		};

		uint16_t port;
	};
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
	
	self->mode = g_module->getServerMode();

	if(strcmp(address, "0.0.0.0") && strcmp(address, "any"))
		self->mode = EmbedPythonModule::PYSRVM_BIND;

	switch(self->mode)
	{
		case EmbedPythonModule::PYSRVM_BIND:	
		{
			NetworkNode localNode = { string(address), port };

			if(strcmp(address, "0.0.0.0") && strcmp(address, "any") && g_module->getEnforceAddress() != "0.0.0.0")
				localNode.name = g_module->getEnforceAddress();

			if(!(self->factory = new PythonEndpointFactory((PyTypeObject *) self->endpointType)))
			{
				Py_DECREF(self->endpointType);
				return 0;
			}

			if(!(self->server = g_daemon->getNetworkManager()->serverStream(&localNode, self->factory, backlog)))
			{
				delete self->factory;
				Py_DECREF(self->endpointType);

				PyErr_Format(PyExc_RuntimeError, "Could not bind socket to '%s':%hu, "
					"it's either in use or the address string is faulty.", localNode.name.c_str(),
					localNode.port);
				return 0;
			}

			break;
		}

		case EmbedPythonModule::PYSRVM_DYNAMIC:
			self->port = port;

			if(!g_module->registerStreamProvider(port, (PyTypeObject *) self->endpointType))
			{
				delete self->factory;
				Py_DECREF(self->endpointType);

				PyErr_Format(PyExc_RuntimeError, "Could not register dynamic stream provider for port :%hu.", port);
				return 0;
			}

			break;
	}

	return (PyObject *) self;
}

static void mwcollectd_NetworkServer_dealloc(mwcollectd_NetworkServer * self)
{
	switch(self->mode)
	{
		case EmbedPythonModule::PYSRVM_BIND:
			if(self->server && !self->server->close(true))
				delete self->server;

			if(self->factory)
				self->factory->decref();

			break;


		case EmbedPythonModule::PYSRVM_DYNAMIC:
			if(self->port)
			{
				g_module->deregisterStreamProvider(self->port);
				self->port = 0;
			}

			break;
	}
	
	Py_XDECREF(self->endpointType);

	Py_TYPE((PyObject *) self)->tp_free(self);
}

static PyObject * mwcollectd_NetworkServer_close(mwcollectd_NetworkServer * self, PyObject * args)
{
	switch(self->mode)
	{
		case EmbedPythonModule::PYSRVM_BIND:
			if(!self->server->close(true))
			{
				PyErr_SetString(PyExc_RuntimeError, "Could not close server socket.");
				return 0;
			}

			self->server = 0;

			Py_RETURN_NONE;


		case EmbedPythonModule::PYSRVM_DYNAMIC:
			if(self->port)
			{
				g_module->deregisterStreamProvider(self->port);
				self->port = 0;
			}

			Py_RETURN_NONE;

		default:
			PyErr_SetString(PyExc_NotImplementedError, __PRETTY_FUNCTION__);
			return 0;
	}
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

static PyObject * mwcollectd_dispatchEvent(PyObject *self, PyObject *args)
{
	const char * name;
	PyObject * props;

	if(!PyArg_ParseTuple(args, "sO!:dispatchEvent", &name, &PyDict_Type, &props))
		return 0;

	Event ev = Event(name);

	{
		Py_ssize_t pos = 0;
		PyObject * key, * value;

		while(PyDict_Next(props, &pos, &key, &value))
		{
			if(!PyUnicode_Check(key))
			{
				PyErr_SetString(PyExc_TypeError, "Key of properties dictionary is not a unicode string.");
				return 0;
			}

			if(PyUnicode_Check(value))
			{
				ev[EmbedPythonModule::toString(key)] = EmbedPythonModule::toString(value);
			}
			else if(PyBytes_Check(value))
			{
				char * buffer;
				Py_ssize_t length;

				if(PyBytes_AsStringAndSize(value, &buffer, &length) < 0)
					return 0;

				ev[EmbedPythonModule::toString(key)] = string(buffer, length);
			}
			else if(PyLong_Check(value))
			{
				int overflow = 0;

				ev[EmbedPythonModule::toString(key)] = PyLong_AsLongAndOverflow(value, &overflow);

				if(overflow)
					return 0;
			}
			else if(PyCObject_Check(value))
			{
				ev[EmbedPythonModule::toString(key)] = PyCObject_AsVoidPtr(value);
			}
			else
			{
				PyErr_Format(PyExc_TypeError, "Type '%s' of property '%s' is invalid.",
					EmbedPythonModule::toString(PyObject_Type(value)).c_str(),
					EmbedPythonModule::toString(key).c_str());
				return 0;
			}

		}
	}

	g_daemon->getEventManager()->fireEvent(&ev);

	Py_RETURN_NONE;
}



static PyMethodDef mwcollectdmethods[] = {
	{ "log", mwcollectd_log, METH_VARARGS,
		"Log given string with given log level." },
	{ "connectStream", mwcollectd_connect, METH_VARARGS,
		"Connect to a given IP, port via TCP." },
	{ "dispatchEvent", mwcollectd_dispatchEvent, METH_VARARGS,
		"Dispatch an event to the other modules." },
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

	if(PyType_Ready(&mwcollectd_NetworkEndpointTimeoutsType) < 0
		|| PyType_Ready(&mwcollectd_NetworkEndpointType) < 0 || PyType_Ready(&mwcollectd_NetworkServerType) < 0)
	{
		return 0;
	}

	if(!(module = PyModule_Create(&mwcollectdmodule)))
		return 0;

	PyModule_AddIntConstant(module, "L_EVENT", (long) LogManager::LL_EVENT);
	PyModule_AddIntConstant(module, "L_SPAM", (long) L_SPAM);
	PyModule_AddIntConstant(module, "L_INFO", (long) L_INFO);
	PyModule_AddIntConstant(module, "L_CRIT", (long) L_CRIT);

	PyModule_AddStringConstant(module, "version", g_daemon->getVersion());

	Py_INCREF(&mwcollectd_NetworkEndpointTimeoutsType);
	PyModule_AddObject(module, "NetworkEndpointTimeouts", (PyObject *) &mwcollectd_NetworkEndpointTimeoutsType);

	Py_INCREF(&mwcollectd_NetworkEndpointType);
	PyModule_AddObject(module, "NetworkEndpoint", (PyObject *) &mwcollectd_NetworkEndpointType);
	
	Py_INCREF(&mwcollectd_NetworkServerType);
	PyModule_AddObject(module, "NetworkServer", (PyObject *) &mwcollectd_NetworkServerType);

	return module;
}



