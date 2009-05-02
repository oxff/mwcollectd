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

#ifndef __MWCOLLECTD_DAEMON_HPP
#define __MWCOLLECTD_DAMEON_HPP


#include <libnetworkd/libnetworkd.hpp>
using namespace libnetworkd;


#ifndef MWCOLLECTD_CORE
#define LOG(format...) m_daemon->getLogManager()->logFormatMessage(format)
#else
#define LOG(format...) g_daemon->getLogManager()->logFormatMessage(format)
#endif


#ifdef __GNUG__
#define __COMPILER__ "g++ " __VERSION__
#else
#define __COMPILER__ "unknown compiler"
#endif

namespace mwcollectd
{


class Daemon
{
public:
	Daemon(const char * configPath);
	virtual ~Daemon();
	
	bool run(char * changeUser = 0);
	
	static inline const char * getVersion()
	{ return (PACKAGE_NAME " v" PACKAGE_VERSION ", compiled on [" __DATE__ " "
		__TIME__ "] with [" __COMPILER__"]"); }
	
	inline NetworkManager * getNetworkManager()
	{ return &m_NetworkManager; }
	inline LogManager * getLogManager()
	{ return &m_LogManager; }
	inline NameResolvingFacility * getNameResolvingFacility()
	{ return m_NameResolvingFacility; }
	inline ModuleManager * getModuleManager()
	{ return &m_ModuleManager; }
	inline EventManager * getEventManager()
	{ return &m_EventManager; }

	inline void stop()
	{ m_active = false; }

protected:
	bool start();

private:
	Configuration * m_Configuration;
	ModuleManager m_ModuleManager;
	NetworkManager m_NetworkManager;
	NameResolvingFacility * m_NameResolvingFacility;
	TimeoutManager m_TimeoutManager;
	EventManager m_EventManager;
	LogManager m_LogManager;

	bool m_active;	
	string m_configBasepath;
};

extern Daemon * g_daemon;


}

#endif // __MWCOLLECTD_DAEMON_HPP
