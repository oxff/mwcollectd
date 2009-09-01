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

#include <Python.h>

#include <string>
#include <vector>
using namespace std;


Daemon * g_daemon;
EmbedPythonModule * g_module;

bool EmbedPythonModule::start(Configuration * config)
{
	vector<string> submodules;

	g_daemon = m_daemon;
	g_module = this;

	{
		if(!config)
		{
			LOG(L_CRIT, "Python extension module loaded without configuration!");
			return false;
		}

		submodules = config->getStringList(":submodules");

		if(submodules.empty())
		{

			LOG(L_CRIT, "No submodules defined for python extension module!");
			return false;
		}
	}
	
	{
		char * prepath = getenv("PYTHONPATH");

		m_modulepath = config->getString(":module-path", PREFIX "/lib/mwcollectd/python");

		if(!prepath || (m_modulepath + ":") != string(prepath).substr(0, m_modulepath.size() + 1))
			setenv("PYTHONPATH", prepath ? (m_modulepath + ":" + prepath).c_str() : m_modulepath.c_str(), 1);
	}


	PyImport_AppendInittab((char *) "mwcollectd", &PyInit_mwcollectd);
	Py_InitializeEx(0);

	for(vector<string>::iterator it = submodules.begin(); it != submodules.end(); ++it)
	{
		PyObject * module = PyImport_ImportModule(it->c_str());

		if(module && !PyErr_Occurred())
		{
			PyObject * fnStart = PyObject_GetAttrString(module, "start");

			if(fnStart && PyCallable_Check(fnStart))
			{
				PyObject * res = PyObject_CallObject(fnStart, 0);

				if(!res)
				{
					LOG(L_CRIT, "Calling start() in '%s' resulted in an error:", it->c_str());
	
					logError();

					Py_Finalize();
					return false;
				}
				else
				{
					if(!PyBool_Check(res) || res != Py_True)
					{
						LOG(L_CRIT, "Module '%s' failed to initialize!", it->c_str());
						LOG(L_SPAM, "%s.start() returned %s", it->c_str(), toString(res).c_str());
						
						Py_Finalize();
						return false;
					}

					Py_DECREF(res);

					m_modules.push_back(module);
				}

				Py_DECREF(fnStart);
			}
			else
			{
				LOG(L_CRIT, "No start() in '%s':", it->c_str());
				logError();

				Py_Finalize();
				return false;
			}
		}
		else
		{
			LOG(L_CRIT, "Could not load submodule '%s':", it->c_str());
			logError();

			Py_Finalize();
			return false;
		}
	}

	{
		string version = Py_GetVersion();

		for(string::iterator it = version.begin(); it != version.end(); ++it)
		{
			if(* it == ' ')
			{
				version.erase(it, version.end());
				break;
			}
		}

		LOG(L_INFO, "Python %s with %u extension module(s) ready.", version.c_str(), submodules.size());
	}

	return true;
}

string EmbedPythonModule::toString(PyObject * obj)
{
	PyObject * res;

	if(!obj)
		return string("<null>");

	if(obj == Py_None)
		return string("None");

	if(PyType_Check(obj))
		return string(((PyTypeObject* ) obj)->tp_name);

	if(!PyUnicode_Check(obj))
	{
		if(!(res = PyObject_Repr(obj)) || !PyUnicode_Check(res))
		{
			Py_XDECREF(res);
			return string("<!repr_res>");
		}
	}
	else
		res = obj;

	Py_ssize_t size = PyUnicode_GetSize(res);
	wchar_t * str = (wchar_t *) malloc((size + 1) * sizeof(wchar_t));
	PyUnicode_AsWideChar((PyUnicodeObject *) res, str, size);
	str[size] = 0;

	if(res != obj)
		Py_DECREF(res);

	size_t csize = wcstombs(0, str, 0);

	if(csize == (size_t) -1)
		return string("<!utf8>");

	char * cstr = (char *) malloc(csize + 1);
	wcstombs(cstr, str, csize + 1);

	string retres = string(cstr);

	free(str);
	free(cstr);

	return retres;
}

void EmbedPythonModule::logError()
{
	if(!PyErr_Occurred())
		return;

	PyObject * type, * value, * traceback;
	PyErr_Fetch(&type, &value, &traceback);

	GLOG(L_CRIT, "  %s: %s", toString(type).c_str(), toString(value).c_str());

	if(!traceback)
		return;
	
	PyObject * name = PyUnicode_FromString("traceback");
	PyObject * module = PyImport_Import(name);
	Py_DECREF(name);

	if(module)
	{
		PyObject * fnStart = PyObject_GetAttrString(module, "extract_tb");

		if(fnStart && PyCallable_Check(fnStart))
		{
			PyObject * args = PyTuple_Pack(1, traceback);
			PyObject * res = PyObject_CallObject(fnStart, args);

			if(res && PyList_Check(res))
			{
				for(size_t k = PyList_GET_SIZE(res); k; --k)
				{
					PyObject * tuple = PyList_GET_ITEM(res, k - 1);
					string p = toString(PyTuple_GET_ITEM(tuple, 0));

					if(p.find(m_modulepath) == 0)
					{
						p.erase(0, m_modulepath.size());

						if(* p.begin() == '/')
							p.erase(0, 1);
					}

					#define TMP(n) (toString(PyTuple_GET_ITEM(tuple, n)).c_str())
					GLOG(L_CRIT, "  %s:%s in %s", p.c_str(), TMP(1), TMP(2));
					GLOG(L_CRIT, "    %s", TMP(3));
					#undef TMP
				}
			}

			Py_XDECREF(res);
			Py_XDECREF(args);
			Py_DECREF(fnStart);
		}

		Py_DECREF(module);
	}
}

bool EmbedPythonModule::stop()
{
	for(list<PyObject *>::iterator it = m_modules.begin();
		it != m_modules.end(); ++it)
	{
		PyObject * fnStop = PyObject_GetAttrString(* it, "stop");

		if(fnStop && PyCallable_Check(fnStop))
		{
			PyObject * res = PyObject_CallObject(fnStop, 0);

			if(!res)
			{
				LOG(L_CRIT, "Calling stop() in '%s' resulted in an error (forcing unload):", toString(* it).c_str());
				logError();

				Py_DECREF(fnStop);
				PyErr_Clear();
			}
			else
			{
				if(!PyBool_Check(res) || res != Py_True)
				{
					LOG(L_SPAM, "%s.stop() returned %s, delaying unload...", toString(* it).c_str(), toString(res).c_str());

					Py_DECREF(fnStop);
					Py_DECREF(res);

					m_modules.erase(m_modules.begin(), it);
					return false;
				}

				Py_DECREF(res);
			}

			Py_DECREF(fnStop);
		}
		else
		{
			LOG(L_SPAM, "No stop() in %s, enforcing unclean unload.", toString(* it).c_str());
			PyErr_Clear();
		}

		Py_DECREF(* it);
	}

	m_modules.clear();

	Py_Finalize();
	return true;
}


EXPORT_LIBNETWORKD_MODULE(EmbedPythonModule, Daemon *);

