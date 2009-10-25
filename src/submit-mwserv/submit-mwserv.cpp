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

#include "submit-mwserv.hpp"

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>


SubmitMwservModule::SubmitMwservModule(Daemon * daemon)
{
	m_daemon = daemon;

	m_heartbeatTimeout = TIMEOUT_EMPTY;
	m_serverAvailable = false;
}

SubmitMwservModule::~SubmitMwservModule()
{
}

bool SubmitMwservModule::start(Configuration * config)
{
	if(!config)
	{
		LOG(L_CRIT, "Cannot load submit-mwserv module without configuration.");
		return false;
	}

	m_guid = config->getString(":mwserv:guid", "");
	m_maintainer = config->getString(":mwserv:maintainer", "");
	m_secret = config->getString(":mwserv:secret", "");
	m_url = config->getString(":mwserv:url", "");

	if(m_guid.empty() || m_maintainer.empty() || m_secret.empty() || m_url.empty())
	{
		LOG(L_CRIT, "Neccessary configuration option for submit-mwserv is missing.");
		return false;
	}

	if(m_url.substr(0, 8) != "https://")
	{
		LOG(L_CRIT, "submit-mwserv URL does not start with \"https://\".");
		return false;
	}

	if(* (-- m_url.end()) != '/')
		m_url.append(1, '/');

	m_retryInterval = config->getInteger(":retry-interval", 180);



	if(!m_daemon->getEventManager()->subscribeEventMask("download.result.success", this)
		|| !m_daemon->getEventManager()->subscribeEventMask("download.result.failure", this)
		|| !m_daemon->getEventManager()->subscribeEventMask("snoop.download", this))
	{
		return false;
	}


	timeoutFired(TIMEOUT_EMPTY);

	return true;
}

bool SubmitMwservModule::stop()
{
	if(m_heartbeatTimeout != TIMEOUT_EMPTY)
	{
		m_daemon->getTimeoutManager()->dropTimeout(m_heartbeatTimeout);
		m_heartbeatTimeout = TIMEOUT_EMPTY;
	}

	if(!m_daemon->getEventManager()->unsubscribeEventMask("download.result.success", this)
		|| !m_daemon->getEventManager()->unsubscribeEventMask("download.result.failure", this))
	{
		return false;
	}

	return true;
}

void SubmitMwservModule::timeoutFired(Timeout t)
{
	m_heartbeatTimeout = TIMEOUT_EMPTY;

	Event ev = Event("download.request");

	ev["url"] = m_url + "heartbeat";
	ev["type"] = "submit-mwserv.heartbeat";

	ev["post:guid"] = m_guid;
	ev["post:maintainer"] = m_maintainer;
	ev["post:secret"] = m_secret;
	ev["post:software"] = m_daemon->getVersion();
	ev["postfields"] = "guid,maintainer,secret,software";
	
	m_daemon->getEventManager()->fireEvent(&ev);
}

void SubmitMwservModule::handleEvent(Event * ev)
{
	if(ev->getName() == "download.result.success")
	{
		if(* (* ev)["type"] == "submit-mwserv.heartbeat")
		{
			const string& response = * (*ev )["response"];

			if(m_heartbeatTimeout != TIMEOUT_EMPTY)
				m_daemon->getTimeoutManager()->dropTimeout(m_heartbeatTimeout);

			if(response.substr(0, 4) == "OK: ")
			{
				char * endptr;
				unsigned long interval = strtoul(response.substr(4).c_str(), &endptr, 0);

				if(* endptr)
					m_heartbeatTimeout = TIMEOUT_EMPTY;
				else
				{
					m_serverAvailable = true;
					m_heartbeatTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(interval, this);
				}
			}
			else
				m_heartbeatTimeout = TIMEOUT_EMPTY;

			if(m_heartbeatTimeout == TIMEOUT_EMPTY)
			{
				m_serverAvailable = false;
				LOG(L_CRIT, "Unexpected mwserv heartbeat response: \"%s\".", response.c_str());

				m_heartbeatTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(m_retryInterval, this);
			}
		}
		else if(* (* ev)["type"] == "submit-mwserv.instance")
		{
			PendingInstanceInfo * info = (PendingInstanceInfo *) (* ev)["opaque"].getPointerValue();

			if(* (* ev)["response"] == "UNKNOWN")
			{

				Event httpev = Event("download.request");

				httpev["url"] = m_url + "botsnoopd/submit";
				httpev["type"] = "submit-mwserv.sample";

				httpev["post:guid"] = m_guid;
				httpev["post:maintainer"] = m_maintainer;
				httpev["post:secret"] = m_secret;

				httpev["post:sha512"] = info->sha512;
				httpev["post:data"] = info->data;

				httpev["postfields"] = "guid,maintainer,secret,sha512,data";

				m_daemon->getEventManager()->fireEvent(&httpev);
			}
			else if(* (* ev)["response"] != "OK")
				LOG(L_CRIT, "Unknown response from mwserv: \"%s\"!", (* ev)["response"].getStringValue().c_str());

			delete info;
		}
	}
	else if(ev->getName() == "download.result.failure")
	{
		if(* (* ev)["type"] == "submit-mwserv.heartbeat")
		{
			if(m_heartbeatTimeout != TIMEOUT_EMPTY)
				m_daemon->getTimeoutManager()->dropTimeout(m_heartbeatTimeout);
			
			m_serverAvailable = false;
			LOG(L_CRIT, "Failed to connect to mwserv server.");

			m_heartbeatTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(m_retryInterval, this);
		}
		else if(* (* ev)["type"] == "submit-mwserv.instance")
		{
			PendingInstanceInfo * info = (PendingInstanceInfo *) (* ev)["opaque"].getPointerValue();

			LOG(L_CRIT, "Submiting instance of \"%s\" from \"%s\", \"%s\" to mwserv failed.",
				info->sha512.c_str(), info->network.c_str(), info->location.c_str());

			delete info;

			
			if(m_heartbeatTimeout != TIMEOUT_EMPTY)
				m_daemon->getTimeoutManager()->dropTimeout(m_heartbeatTimeout);

			m_serverAvailable = false;
			m_heartbeatTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(m_retryInterval, this);
		}
		else if(* (* ev)["type"] == "submit-mwserv.sample")
		{
			LOG(L_CRIT, "Sample upload to mweserv failed, disabling mwserv temporarily...");

			if(m_heartbeatTimeout != TIMEOUT_EMPTY)
				m_daemon->getTimeoutManager()->dropTimeout(m_heartbeatTimeout);

			m_serverAvailable = false;
			m_heartbeatTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(m_retryInterval, this);
		}
	}
	else if(ev->getName() == "shellcode.file")
	{
		if(!m_serverAvailable)
		{
			LOG(L_SPAM, "Ignoring submission of \"%s\" instance since server is unavailable.",
				(* ev)["sha512"].getStringValue().c_str());

			return;
		}

		PendingInstanceInfo * info = new PendingInstanceInfo;

		info->sha512 = * (* ev)["sha512"];
		info->network = * (* ev)["network"];
		info->location = * (* ev)["location"];
		info->data = string((char *) (* ev)["data"].getPointerValue(), (* ev)["datasize"].getIntegerValue());


		Event httpev = Event("download.request");

		httpev["url"] = m_url + "botsnoopd/submit";
		httpev["type"] = "submit-mwserv.instance";
		httpev["opaque"] = (void *) info;

		httpev["post:guid"] = m_guid;
		httpev["post:maintainer"] = m_maintainer;
		httpev["post:secret"] = m_secret;

		httpev["post:sha512"] = * (* ev)["sha512"];

		httpev["postfields"] = "guid,maintainer,secret,sha512,network,location";

		m_daemon->getEventManager()->fireEvent(&httpev);
	}
}



EXPORT_LIBNETWORKD_MODULE(SubmitMwservModule, Daemon *);
