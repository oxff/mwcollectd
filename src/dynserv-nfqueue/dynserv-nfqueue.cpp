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

#include "dynserv-nfqueue.hpp"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>
#include <time.h>


DynamicServerNfqueue::DynamicServerNfqueue(Daemon * daemon)
{
	m_daemon = daemon;
}


static int nfqueue_trampoline(struct nfq_q_handle * queue,
	struct nfgenmsg * message, struct nfq_data * data, void * parent)
{
	((DynamicServerNfqueue *) parent)->handlePacket(queue, message, data);
	return 0;
}

bool DynamicServerNfqueue::start(Configuration * moduleConfiguration)
{
	if(!moduleConfiguration)
		return false;

	if(!setRanges(moduleConfiguration->getString(":monitor:port-range", "0-65535")))
		return false;

	m_hitLimit = moduleConfiguration->getInteger(":rate-limit:hits", 0);
	m_limitTimeout = moduleConfiguration->getInteger("rate-limit:timeout", 180);

	if((m_netfilterHandle = nfq_open()) == 0)
	{
		LOG(L_CRIT, "Could not open NFQUEUE handle!");
		return false;
	}

	if(nfq_unbind_pf(m_netfilterHandle, AF_INET) != 0)
	{
		LOG(L_CRIT, "Could not unbind AF_INET from NFQUEUE handle: %s",
			strerror(errno));
		return false;
	}

	if(nfq_bind_pf(m_netfilterHandle, AF_INET) != 0)
	{
		LOG(L_CRIT, "Could not rebind AF_INET to NFQUEUE handle (root?): %s",
			strerror(errno));
		return false;
	}

	int queue = moduleConfiguration->getInteger(":monitor:queue", 0);


	if((m_queueHandle = nfq_create_queue(m_netfilterHandle, queue,
		nfqueue_trampoline, this)) == 0)
	{
		LOG(L_CRIT, "Could not create NFQUEUE queue #%u: %s", queue,
			strerror(errno));
		return false;
	}

	if(nfq_set_mode(m_queueHandle, NFQNL_COPY_PACKET, 0x1000) != 0)
	{
		LOG(L_CRIT, "Could not set NFQUEUE mode NFQNL_COPY_PACKET: %s",
			strerror(errno));
		return false;
	}

	if((m_fd = nfq_fd(m_netfilterHandle)) < 0)
	{
		LOG(L_CRIT, "Could not obtain NFQUEUE file descriptor: %s",
			strerror(errno));
		return false;
	}

	m_ioSocketState = IOSOCKSTAT_IDLE;
	m_daemon->getNetworkManager()->addSocket(this, m_fd);

	return true;
}

bool DynamicServerNfqueue::stop()
{
	if(m_queueHandle)
	{
		nfq_destroy_queue(m_queueHandle);
		m_queueHandle = 0;
	}

	if(m_netfilterHandle)
	{
		nfq_close(m_netfilterHandle);
		m_netfilterHandle = 0;
	}

	if(m_rateLimitingTimeout != TIMEOUT_EMPTY)
	{
		m_daemon->getTimeoutManager()->dropTimeout(m_rateLimitingTimeout);
		m_rateLimitingTimeout = TIMEOUT_EMPTY;
	}

	return true;
}

void DynamicServerNfqueue::pollRead()
{
	static char buffer[0x1000 + 60];
	int length;

	if((length = recv(m_fd, buffer, sizeof(buffer), 0)) <= 0
		|| nfq_handle_packet(m_netfilterHandle, buffer, length) != 0)
	{
		LOG(L_CRIT, "Failed to pass netfilter data: %s", strerror(errno));

		m_daemon->stop();
	}
	
	m_ioSocketState = IOSOCKSTAT_IDLE;
}

inline void DynamicServerNfqueue::handlePacket(struct nfq_q_handle * queue,
	struct nfgenmsg * message, struct nfq_data * data)
{
	struct nfqnl_msg_packet_hdr * header;
	char * payload;
	int length;

	if((header = nfq_get_msg_packet_hdr(data)) == 0)
	{
		LOG(L_CRIT, "Failed to get NFQUEUE packet header.");
		m_daemon->stop();
	}

	if((length = nfq_get_payload(data, &payload)) <= 0)
		return;

	if((size_t) length >= sizeof(struct iphdr))
	{
		struct iphdr * ipHeader = (struct iphdr *) payload;

		if(ipHeader->protocol == IPPROTO_TCP && (size_t) length >=
			ipHeader->ihl * 4 + sizeof(struct tcphdr))
		{
			struct tcphdr * tcpHeader = (struct tcphdr *)
				(payload + ipHeader->ihl * 4);
			uint16_t port = ntohs(tcpHeader->dest);
			uint32_t address = ipHeader->daddr;

			if(tcpHeader->syn && !tcpHeader->ack
				&& !tcpHeader->rst && !tcpHeader->fin
				&& (address & 0xff) != 0x7f)
			{
				if(limitSource(ipHeader->saddr))
				{
					char daddrBuf[16];

					if(nfq_set_verdict(m_queueHandle, ntohl(header->packet_id),
						NF_DROP, 0, 0) < 0)
					{
						LOG(L_CRIT, "Failed to set NFQUEUE verdict: %s", strerror(errno));
						m_daemon->stop();
					}

					strcpy(daddrBuf, inet_ntoa(* (struct in_addr *) &ipHeader->daddr));

					LOG(L_SPAM, "Rate limiting SYN from %s to %s:%u.",
						inet_ntoa(* (struct in_addr *) &ipHeader->saddr),
						daddrBuf, ntohs(tcpHeader->dest));

					return;
				}

				if(monitorPort(port))
				{
					Event ev = Event("stream.request");

					ev["address"] =
						string(inet_ntoa(* (struct in_addr *) &address));
					ev["port"] = port;
					ev["protocol"] = "tcp";

					m_daemon->getEventManager()->fireEvent(&ev);
				}
				else
				{
					LOG(L_SPAM, "Ignored TCP packet %s:%u via NFQUEUE", 
						inet_ntoa(* (struct in_addr *) &address), port);
				}
			}
		}
	}

	if(nfq_set_verdict(m_queueHandle, ntohl(header->packet_id),
		NF_ACCEPT, 0, 0) < 0)
	{
		LOG(L_CRIT, "Failed to set NFQUEUE verdict: %s", strerror(errno));
		m_daemon->stop();
	}
}

bool DynamicServerNfqueue::setRanges(const char * range)
{
	const char * walk;
	uint16_t port = 0, port2 = 0;
	enum
	{
		S_PARSENUM,
		S_PARSENUM2,
	} state;

	for(walk = range, state = S_PARSENUM;; ++walk)
	{
		switch(state)
		{
		case S_PARSENUM:
			if(* walk >= '0' && * walk <= '9')
				port = port * 10 + (* walk  - '0');
			else if(* walk == '-')
				state = S_PARSENUM2;
			else if(* walk == ',' || ! * walk)
			{
				if(!addRange(port, 0))
					return false;

				port = port2 = 0;
			}
			else
			{
				LOG(L_CRIT, "Unexpected literal '%c' in port range at "
					"offset %u!", * walk, walk - range);
				return false;
			}

			break;

		case S_PARSENUM2:
			if(* walk >= '0' && * walk <= '9')
				port2 = port2 * 10 + (* walk  - '0');
			else if(* walk == ',' || ! * walk)
			{
				if(port2 < port)
				{
					LOG(L_CRIT, "Inverted range %u <- %u at offset"
						" %u!", port, port2, walk - range);
					return false;
				}

				if(!addRange(port, port2 - port))
					return false;

				port = port2 = 0;

				state = S_PARSENUM;
			}
			else
			{
				LOG(L_CRIT, "Unexpected literal '%c' in port range at "
					"offset %u!", * walk, walk - range);
				return false;
			}
		}

		if(! * walk)
			break;
	}

	return true;
}

bool DynamicServerNfqueue::addRange(uint16_t port, uint16_t length)
{
	PortRange range = { port, length };
	PortSet::iterator it = m_ports.lower_bound(range);

	if(it != m_ports.end() && it->port <= port + length)
	{
		LOG(L_CRIT, "Range %u -> %u intersects with %u -> %u.",
			port, port + length, it->port, it->port + it->length);
		return false;
	}

	m_ports.insert(range);
	return true;
}

bool DynamicServerNfqueue::monitorPort(uint16_t port)
{
	PortRange range = { port, 0 };
	PortSet::iterator it = m_ports.lower_bound(range);

	if(it == m_ports.end() || !(port >= it->port && port <= it->port + it->length))
		return false;

	return true;
}

bool DynamicServerNfqueue::limitSource(uint32_t address)
{
	RateLimitMap::iterator jt;

	if(!m_hitLimit)
		return false;

	jt = m_RateLimitMap.find(address);

	if(jt != m_RateLimitMap.end())
	{
		if(jt->second->hits >= m_hitLimit)
			return true;

		++jt->second->hits;
	}
	else
	{
		if(m_RateLimitQueue.empty())
			m_rateLimitingTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(m_limitTimeout, this);

		RateLimit rl;

		rl.hits = 1;
		rl.firstTimestamp = time(0);

		RateLimitQueue::iterator queueIterator = m_RateLimitQueue.insert(m_RateLimitQueue.end(), rl);
		RateLimitMap::iterator mapIterator = m_RateLimitMap.insert(RateLimitMap::value_type(address, queueIterator)).first;

		queueIterator->mapEntry = mapIterator;
	}

	return false;
}

void DynamicServerNfqueue::timeoutFired(Timeout timeout)
{
	time_t now = time(0);
	ASSERT(timeout == m_rateLimitingTimeout);
	RateLimitQueue::iterator it;

	for(it = m_RateLimitQueue.begin(); it != m_RateLimitQueue.end() && it->firstTimestamp + m_limitTimeout < now; ++it)
		m_RateLimitMap.erase(it->mapEntry);

	m_RateLimitQueue.erase(m_RateLimitQueue.begin(), it);

	if(!m_RateLimitQueue.empty())
	{
		m_rateLimitingTimeout = m_daemon->getTimeoutManager()->scheduleTimeout(m_limitTimeout - (now -
			m_RateLimitQueue.front().firstTimestamp), this);
	}
	else
		m_rateLimitingTimeout = TIMEOUT_EMPTY;
}


EXPORT_LIBNETWORKD_MODULE(DynamicServerNfqueue, Daemon *);

