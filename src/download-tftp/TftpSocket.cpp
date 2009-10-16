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

#include "download-tftp.hpp"

#include <sys/types.h>
#include <sys/socket.h>

#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>



TftpSocket::~TftpSocket()
{
	if(m_timeout != TIMEOUT_EMPTY)
		g_daemon->getTimeoutManager()->dropTimeout(m_timeout);
}

bool TftpSocket::sendRequest()
{
	if(m_socket < 0)
	{
		if((m_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			return false;

		if(fcntl(m_socket, F_SETFL, O_NONBLOCK) < 0)
		{
			GLOG(L_CRIT, "%s.fcntl: %s", __PRETTY_FUNCTION__, strerror(errno));

			close(m_socket);
			m_socket = -1;

			return false;
		}

		m_port = htons(69);
		m_ackId = 0;
	
		m_successiveTimeouts = 1;
		g_daemon->getTimeoutManager()->scheduleTimeout(3, this);
	}

	size_t size = sizeof(uint16_t) + (m_filename.size() + 1) + 6;
	uint8_t request[size];

	* (uint16_t *) request = htons(1);
	strcpy((char *) &request[sizeof(uint16_t)], m_filename.c_str());
	strcpy((char *) &request[size - 6], "octet");

	struct sockaddr_in peer;

	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = m_address;
	peer.sin_port = m_port;


	if(sendto(m_socket, request, size, 0, (struct sockaddr *) &peer, sizeof(peer)) < 0)
	{
		GLOG(L_CRIT, "%s.sendto: %s", __PRETTY_FUNCTION__, strerror(errno));

		close(m_socket);
		m_socket = -1;

		return false;
	}

	m_ioSocketState = IOSOCKSTAT_IDLE;
	return true;
}

void TftpSocket::sendAck()
{
	struct {
		uint16_t opcode;
		uint16_t block;
	} __attribute__((packed)) packet;

	packet.opcode = htons(4);
	packet.block = m_ackId;

	struct sockaddr_in peer;

	peer.sin_family = AF_INET;
	peer.sin_port = m_port;
	peer.sin_addr.s_addr = m_address;

	if(sendto(m_socket, (char *) &packet, sizeof(packet), 0, (struct sockaddr *) &peer, sizeof(peer)) < 0)
		GLOG(L_INFO, "%s.sendto: %s", __PRETTY_FUNCTION__, strerror(errno));
}

void TftpSocket::pollRead()
{
	int read;
	uint8_t pktbuffer[516];
	struct sockaddr_in peer;
	socklen_t addrsize = sizeof(peer);

	if((read = recvfrom(m_socket, pktbuffer, sizeof(pktbuffer), 0, (struct sockaddr *) &peer, &addrsize)) < 0)
	{
		if(errno == EAGAIN || errno == EWOULDBLOCK)
			return;

		GLOG(L_CRIT, "Could not read from TFTP socket for %s/%s!",
			inet_ntoa(* (struct in_addr *) &m_address), m_filename.c_str());

		m_parent->transferFailed(this);
		return;
	}

	if(peer.sin_addr.s_addr != m_address)
	{
		GLOG(L_CRIT, "Ignoring unexpected TFTP packet from \"%s\" where it should be coming from \"%08x\"!",
			inet_ntoa(peer.sin_addr), m_address);

		return;
	}

	switch(ntohs(* (uint16_t *) pktbuffer))
	{
		case 3:
			if(ntohs(* (uint16_t *) &pktbuffer[sizeof(uint16_t)]) != m_ackId + 1)
			{
				GLOG(L_SPAM, "Ignoring out of order TFTP packet from %s/%s: %04hx != %04hx.",
					inet_ntoa(peer.sin_addr), m_filename.c_str(), ntohs(* (uint16_t *) pktbuffer),
					m_ackId + 1);

				return;
			}

			if(!m_ackId)
				m_port = peer.sin_port;
			else if(m_port != peer.sin_port)
			{
				GLOG(L_CRIT, "TFTP source port from %s/%s changed after first DATA packet!",
					inet_ntoa(peer.sin_addr), m_filename.c_str());

				m_parent->transferFailed(this);
				return;
			}

			m_successiveTimeouts = 1;

			if(m_timeout != TIMEOUT_EMPTY)
				g_daemon->getTimeoutManager()->dropTimeout(m_timeout);

			m_timeout = g_daemon->getTimeoutManager()->scheduleTimeout(3, this);

			++ m_ackId;
			sendAck();

			m_dataBuffer.append((char *) &pktbuffer[sizeof(uint16_t) * 2], read - sizeof(uint16_t) * 2);

			if(read < 516)
				m_parent->transferSucceeded(this, m_dataBuffer);

			return;

		case 5:
			if(pktbuffer[read - 1] != 0)
				pktbuffer[read - 1] = 0;

			GLOG(L_CRIT, "TFTP %s/%s error [%hi]: \"%s\"",
				inet_ntoa(peer.sin_addr), m_filename.c_str(), ntohs(* ((uint16_t *) &pktbuffer[sizeof(uint16_t)])),
				&pktbuffer[sizeof(uint16_t) * 2]);

			m_parent->transferFailed(this);
			
			return;


		default:
			GLOG(L_CRIT, "Unexpected TFTP opcode %u from %s downloading %s!",
				ntohs(* (uint16_t *) pktbuffer), inet_ntoa(peer.sin_addr), m_filename.c_str());

			m_parent->transferFailed(this);
			
			return;
	}
}

void TftpSocket::pollError()
{
	m_parent->transferFailed(this);
}

void TftpSocket::timeoutFired(Timeout to)
{
	if(m_successiveTimeouts > 5)
	{
		GLOG(L_INFO, "TFTP transfer of %s/%s failed after %u successive timeouts.",
			inet_ntoa(* (struct in_addr *) &m_address), m_filename.c_str(), m_successiveTimeouts - 1);

		m_timeout = TIMEOUT_EMPTY;
		m_parent->transferFailed(this);
		return;
	}

	if(m_ackId == 0)
	{
		GLOG(L_SPAM, "Initial TFTP response for %s/%s timed out after %u seconds, retrying.",
			inet_ntoa(* (struct in_addr *) &m_address), m_filename.c_str(), m_successiveTimeouts * 3);
		sendRequest();
	}
	else
	{
		GLOG(L_SPAM, "Data TFTP response #%u for %s/%s timed out after %u seconds, retrying.", m_ackId,
			inet_ntoa(* (struct in_addr *) &m_address), m_filename.c_str(), m_successiveTimeouts * 3);

		sendAck();
	}
	
	++m_successiveTimeouts;
	m_timeout = g_daemon->getTimeoutManager()->scheduleTimeout(m_successiveTimeouts * 3, this);
}
