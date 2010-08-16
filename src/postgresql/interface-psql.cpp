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

#include "interface-psql.hpp"


Daemon * g_daemon;


InterfacePostgres::InterfacePostgres(Daemon * daemon)
{
	m_daemon = daemon;
	m_socket = 0;
}


bool InterfacePostgres::start(Configuration * moduleConfiguration)
{
	m_reconnectTimeout = TIMEOUT_EMPTY;
	
	m_unloading = false;
	
	if(!(m_config = moduleConfiguration))
		return false;
	
	if(m_config->nodeType(":server:host") == CFGNT_NONE ||
		m_config->nodeType(":server:user") == CFGNT_NONE ||
		m_config->nodeType(":server:database") == CFGNT_NONE)
	{
		LOG(L_CRIT, "Missing host / user / database in postgresql configuration!");
		return false;
	}
	
	m_socket = 0;
	m_host = m_config->getString(":server:host", "");
	m_daemon->getNameResolvingFacility()->resolveName(m_host, this);

	m_daemon->getEventManager()->subscribeEventMask("postgresql.prepare", this, true);
	m_daemon->getEventManager()->subscribeEventMask("postgresql.query", this, true);
	
	return true;
}

bool InterfacePostgres::stop()
{
	m_daemon->getEventManager()->unsubscribeAll(this);	
	m_daemon->getNameResolvingFacility()->cancelResolutions(this);
	
	if(!m_socket)
		return true;

	m_unloading = true;
	m_socket->closeConnection();

	return false;
}


void InterfacePostgres::nameResolved(string name, list<string> addresses,
	NameResolutionStatus status)
{
	if(m_unloading)
		return;

	if(status != NRS_OK)
	{
		LOG(L_CRIT, "Could not resolve \"%s\" as PostgreSQL server!", name.c_str());
		
		if(!m_socket && m_reconnectTimeout == TIMEOUT_EMPTY)
		{
			m_reconnectTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(
				m_config->getInteger(":reconnect-timeout", 20), this);
		}
		
		return;
	}
	
	if(m_socket)
		return;

	m_socket = new PostgresSocket(m_daemon, m_config, addresses.front(), this);
	m_daemon->getNetworkManager()->addSocket(m_socket, m_socket->getSocket());
	
	m_socket->setNotifyHandler(this);
}

void InterfacePostgres::timeoutFired(Timeout timeout)
{	
	if(timeout == m_reconnectTimeout)
	{
		m_reconnectTimeout = TIMEOUT_EMPTY;
		
		m_daemon->getNameResolvingFacility()->resolveName(
			m_config->getString(":server:host", ""), this);
	}
}

void InterfacePostgres::connectionDead(PostgresSocket * socket)
{
	if(m_socket == socket)
	{
		if(!m_unloading && m_reconnectTimeout == TIMEOUT_EMPTY)
		{
			m_reconnectTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(
				m_config->getInteger(":reconnect-timeout", 20), this);
		}
			
		m_socket = 0;
	}
	
	m_daemon->getNetworkManager()->removeSocket(socket);	
	delete socket;
	
	m_taskQueue = queue<TaskInfo>();
	
	if(m_unloading)
		m_daemon->stop();
}

void InterfacePostgres::queryCompleted(bool success, QueryResult * result,
	bool binary)
{	
	TaskInfo& info = m_taskQueue.front();

	if(!success)
		LOG(L_CRIT, "Query \"%s\" of %s failed!", info.id.c_str(), info.module.c_str());

	Event ev = Event("postgresql.query.result");

	ev["success"] = success;
	ev["module"] = info.module;
	ev["id"] = info.id;

	if(success && result)
	{
		ev["result"] = (void *) result;
	}
	
	m_daemon->getEventManager()->fireEvent(&ev);
	m_taskQueue.pop();
}

void InterfacePostgres::notifyArrived(string name)
{
	Event ev = Event("postgresql.notify");

	ev["name"] = name;
	m_daemon->getEventManager()->fireEvent(&ev);
}

void InterfacePostgres::handleEvent(Event * ev)
{
	if(!m_socket || m_unloading)
		return;

	if(!ev->hasAttribute("module") || !ev->hasAttribute("id"))
	{
		LOG(L_CRIT, "No module / id information in event: %s", ev->toString().c_str());
		return;
	}

	if(ev->getName() == "postgresql.prepare")
	{
		m_taskQueue.push(TaskInfo(* (* ev)["module"], * (* ev)["id"]));
		m_socket->prepareStatement(* (* ev)["name"], * (* ev)["query"], this);
	}
	else if(ev->getName() == "postgresql.query")
	{
		if(ev->hasAttribute("query"))
		{
			m_taskQueue.push(TaskInfo(* (* ev)["module"], * (* ev)["id"]));
			m_socket->sendQuery(* (* ev)["query"], this);
		}
		else if(ev->hasAttribute("name"))
		{
			m_taskQueue.push(TaskInfo(* (* ev)["module"], * (* ev)["id"]));
			m_socket->sendPreparedQuery(* (* ev)["name"], true, this);
		}
	}
}

void InterfacePostgres::prepareCompleted(string name, bool success)
{
	TaskInfo& info = m_taskQueue.front();

	if(!success)
		LOG(L_CRIT, "Preparation of \"%s\"/\"%s\" of %s failed!", name.c_str(), info.id.c_str(), info.module.c_str());

	Event ev = Event("postgresql.prepare.result");

	ev["success"] = success;
	ev["module"] = info.module;
	ev["id"] = info.id;
	ev["name"] = name;
	
	m_daemon->getEventManager()->fireEvent(&ev);
	m_taskQueue.pop();
}


EXPORT_LIBNETWORKD_MODULE(InterfacePostgres, Daemon *);

