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

#include <mwcollectd.hpp>
using namespace mwcollectd;


#ifndef __MWCOLLECTD_SUBMITMWSERV_HPP
#define __MWCOLLECTD_SUBMITMWSERV_HPP


class SubmitMwservModule : public Module, public EventSubscriber,
	public TimeoutReceiver
{
public:
	SubmitMwservModule(Daemon * daemon);	
	virtual ~SubmitMwservModule();

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();
	
	virtual const char * getName() { return "submit-mwserv"; }
	virtual const char * getDescription() { return "Submit downloaded"
		" malware binaries through the mwserv interface."; }

	virtual void timeoutFired(Timeout t);
	
	virtual void handleEvent(Event * firedEvent);

protected:
	struct PendingInstanceInfo
	{
		string sha512, network, location;
		string data;
	};

private:
	Daemon * m_daemon;

	string m_guid, m_maintainer, m_secret, m_url;

	Timeout m_heartbeatTimeout;
	bool m_serverAvailable;
	uint32_t m_retryInterval;
};


#endif // __MWCOLLECTD_SUBMITMWSERV_HPP

