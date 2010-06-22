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

void PythonTimeout::schedule(PyObject * receiver, size_t seconds)
{
	if(m_timeout != TIMEOUT_EMPTY)
		g_daemon->getTimeoutManager()->dropTimeout(m_timeout);

	m_receiver = receiver;
	Py_INCREF(m_receiver);

	m_timeout = g_daemon->getTimeoutManager()->scheduleTimeout(seconds, this); 
}

PythonTimeout::~PythonTimeout()
{
	if(m_timeout != TIMEOUT_EMPTY)
	{
		g_daemon->getTimeoutManager()->dropTimeout(m_timeout);
		Py_DECREF(m_receiver);
	}
}

void PythonTimeout::timeoutFired(Timeout t)
{
	ASSERT(t == m_timeout);
	m_timeout = TIMEOUT_EMPTY;

	PyObject * args = Py_BuildValue("(O)", m_pyTimeout);
	PyObject * res = PyObject_CallObject(m_receiver, args);

	Py_DECREF(m_receiver);
	
	if(!res)
	{
		GLOG(L_CRIT, "Calling attribute timeout receiver %s failed:", 
			EmbedPythonModule::toString((PyObject *) m_receiver).c_str());

		g_module->logError();
		PyErr_Clear();
	
		Py_XDECREF(args);
		return;
	}

	Py_XDECREF(args);
	Py_DECREF(res);
}

