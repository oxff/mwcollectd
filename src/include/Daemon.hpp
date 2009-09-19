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

#include <libnetworkd/libnetworkd.hpp>
using namespace libnetworkd;

#include "HashManager.hpp"

#include <list>

#ifndef __MWCOLLECTD_DAEMON_HPP
#define __MWCOLLECTD_DAEMON_HPP


#ifndef MWCOLLECTD_CORE
#define LOG(level, format...) m_daemon->getLogManager()->logFormatMessage(level, format)
#define GLOG(level, format...) ::g_daemon->getLogManager()->logFormatMessage(level, format)
#else
#define LOG(level, format...) g_daemon->getLogManager()->logFormatMessage(level, format)
#endif

#define L_SPAM	LogManager::LL_SPAM
#define L_INFO	LogManager::LL_INFO
#define L_CRIT	LogManager::LL_CRITICAL


#ifdef __GNUG__
#define __COMPILER__ "g++ " __VERSION__
#else
#define __COMPILER__ "unknown compiler"
#endif


namespace mwcollectd
{


class CoreLoopable
{
public:
	virtual ~CoreLoopable() { }

	virtual void loop() = 0;
	virtual bool computationPending()
	{ return false; }
};

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
	inline TimeoutManager * getTimeoutManager()
	{ return &m_TimeoutManager; }
	inline HashManager * getHashManager()
	{ return &m_HashManager; }

	inline void stop()
	{ m_active = false; }

	inline void registerLoopable(CoreLoopable * p)
	{ m_loopables.push_back(p); }
	inline void unregisterLoopable(CoreLoopable * p)
	{ m_loopables.remove(p); }

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
	HashManager m_HashManager;

	bool m_active;	
	string m_configBasepath;

	std::list<CoreLoopable *> m_loopables;
};

#ifdef MWCOLLECTD_CORE
extern Daemon * g_daemon;
#endif


}

#endif // __MWCOLLECTD_DAEMON_HPP
