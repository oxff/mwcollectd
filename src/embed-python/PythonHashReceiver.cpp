/*
 *				    _ _           _      _ 
 *	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
 *	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
 *	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
 *	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
 *
 *
 * 	Copyright 2010 Georg Wicherski, Kaspersky Labs GmbH
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

PythonHashReceiver::PythonHashReceiver(PyObject * receiverFn, PyObject * toBeHashed, HashType type) :
	m_receiverFn(receiverFn), m_2bhashed(toBeHashed)
{
	m_pythonObject.receiver = this;

	Py_INCREF(m_2bhashed);
	Py_INCREF(m_receiverFn);

	g_daemon->getHashManager()->computeHash(this, type, (uint8_t *) PyBytes_AS_STRING(toBeHashed),
		PyBytes_GET_SIZE(toBeHashed));
}

PythonHashReceiver::~PythonHashReceiver()
{
	g_daemon->getHashManager()->dropReceiver(this);
}

void PythonHashReceiver::hashComputed(HashType type, uint8_t * data,
	unsigned int dataLength, uint8_t * hash, unsigned int hashLength)
{
	PyObject * args = Py_BuildValue("(iOy#)", (long) type, m_2bhashed, hash, hashLength);
	PyObject * res = PyObject_CallObject(m_receiverFn, args);

	if(!res)
	{
		GLOG(L_CRIT, "Invoking hash receiver %s failed:", 
			EmbedPythonModule::toString((PyObject *) m_receiverFn).c_str());

		Py_DECREF(m_receiverFn);

		g_module->logError();
		PyErr_Clear();
	
		Py_XDECREF(args);
		return;
	}

	Py_DECREF(m_receiverFn);
	Py_XDECREF(args);
	Py_DECREF(res);

	Py_DECREF(m_2bhashed);
	Py_DECREF(&m_pythonObject);
}
