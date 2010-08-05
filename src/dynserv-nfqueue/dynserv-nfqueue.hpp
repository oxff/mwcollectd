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


#ifndef __MWCOLLECTD_DYNSERVNFQUEUE_HPP
#define __MWCOLLECTD_DYNSERVNFQUEUE_HPP

#include <mwcollectd.hpp>
using namespace mwcollectd;

extern "C" {
	#include <linux/netfilter.h>
	#include <libnetfilter_queue/libnetfilter_queue.h>
}

#include <list>
#include <set>
#include <tr1/unordered_map>
using namespace std;
using namespace std::tr1;

#include <time.h>


class DynamicServerNfqueue : public Module, public IOSocket, public TimeoutReceiver
{
public:
	DynamicServerNfqueue(Daemon * daemon);
	virtual ~DynamicServerNfqueue() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "dynserv-nfqueue"; }
	virtual const char * getDescription() { return "Dynamically create TCP"
		" servers based on incoming SYN packets via NFQUEUE."; }

	virtual void pollRead();
	virtual void pollError() { pollRead(); }
	virtual void pollWrite() { }

	virtual void timeoutFired(Timeout timeout);

	void handlePacket(struct nfq_q_handle * queue, struct nfgenmsg *
		message, struct nfq_data * data);

protected:
	bool setRanges(const char * range);
	bool limitSource(uint32_t address);
	bool monitorPort(uint16_t port);

private:
	bool addRange(uint16_t port, uint16_t length);
	Daemon * m_daemon;

	struct PortRange
	{
		uint16_t port;
		uint16_t length;

		bool operator()(PortRange a, PortRange b)
		{ return a.port + a.length < b.port; }
	};

	struct nfq_handle * m_netfilterHandle;
	struct nfq_q_handle * m_queueHandle;
	int m_fd;

	typedef set<PortRange, PortRange> PortSet;
	PortSet m_ports;

	struct RateLimit
	{
		size_t hits;
		time_t firstTimestamp;
		uint32_t address;
	};

	typedef list<RateLimit> RateLimitQueue;
	typedef unordered_map<uint32_t, RateLimit *> RateLimitMap;

	RateLimitQueue m_RateLimitQueue;
	RateLimitMap m_RateLimitMap;
	size_t m_hitLimit;
	time_t m_limitTimeout;
	Timeout m_rateLimitingTimeout;
};


#endif // __MWCOLLECTD_DYNSERVNFQUEUE_HPP
