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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "shellcode-libemu.hpp"


EmulatorSocket::~EmulatorSocket()
{
	if(m_fd >= 0)
		close(m_fd);

	m_ioSocketState = IOSOCKSTAT_IGNORE;
}

void EmulatorSocket::pollRead()
{
	switch(m_state)
	{
		case SS_CONNECTING:
		{
			m_session->socketWakeup(1);
			m_state = SS_CONNECTED;
			m_ioSocketState = IOSOCKSTAT_IGNORE;

			break;
		}

		case SS_LISTENING:
		{
			uint8_t buf[m_rsize];
			socklen_t len = m_rsize;
			int res = ::accept(m_fd, m_rbuf ? (struct sockaddr *) buf : 0, m_rbuf ? &len : 0);

			if(res < 0)
			{
				if(errno == EAGAIN || errno == EWOULDBLOCK)
					return;

				m_ioSocketState = IOSOCKSTAT_IGNORE;
				m_state = SS_LISTENING;
				m_session->socketWakeup(res);

				return;
			}				

			if(m_rbuf)
			{
				if(emu_memory_write_block(m_memory, m_rbuf, buf, len) < 0)
				{
					m_session->socketWakeup(-1);
					return;
				}
			}

			res = m_session->registerSocket(new EmulatorSocket(res, m_session, m_memory));

			m_session->socketWakeup(res);
			m_rbuf = 0;			
			m_ioSocketState = IOSOCKSTAT_IGNORE;

			break;
		}

		case SS_CONNECTED:
		{
			uint8_t buf[m_rsize];
			int read = recv(m_fd, buf, m_rsize, 0);

			if(read <= 0)
			{
				if(read < 0 && errno == ECONNRESET)
					read = 0;

				m_ioSocketState = IOSOCKSTAT_IGNORE;
				m_state = SS_UNINIT;
				m_session->socketWakeup(read);

				return;
			}				

			if(emu_memory_write_block(m_memory, m_rbuf, buf, read) < 0)
			{
				m_session->socketWakeup(-1);
				return;
			}

			m_session->socketWakeup(read);
			m_rbuf = 0;
			
			if(m_ioSocketState == IOSOCKSTAT_IDLE)
				m_ioSocketState = IOSOCKSTAT_IGNORE;

			break;
		}

		default:
			break;
	}
}

void EmulatorSocket::pollError()
{
	m_session->socketWakeup(-1);
	m_state = SS_UNINIT;
	m_ioSocketState = IOSOCKSTAT_IGNORE;
}

void EmulatorSocket::pollWrite()
{
	if(m_state != SS_CONNECTED)
		return;

	int written = send(m_fd, m_outputBuffer.data(), m_outputBuffer.size(), 0);

	if(written <= 0)
	{
		if(written == 0 || (errno != EWOULDBLOCK && errno != EAGAIN))
			m_session->socketWakeup(written);

		if(m_rbuf)
			m_ioSocketState = IOSOCKSTAT_IDLE;
		else
			m_ioSocketState = IOSOCKSTAT_IGNORE;
	}
	else
	{
		m_outputBuffer.erase(0, written);

		if(m_outputBuffer.empty())
			m_session->socketWakeup(m_wsize);
	}

	if(m_rbuf)
		m_ioSocketState = IOSOCKSTAT_IDLE;
	else
		m_ioSocketState = IOSOCKSTAT_IGNORE;
}

bool EmulatorSocket::socket()
{
	if((m_fd = ::socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return false;

	if(fcntl(m_fd, F_SETFL, O_NONBLOCK) < 0)
	{
		m_fd = -1;
		return false;
	}

	return true;
}

int EmulatorSocket::read(uint32_t guestbuf, size_t length)
{
	if(length > 1024)
		length = 1024;

	uint8_t buf[length];
	int read;

	if(m_state != SS_CONNECTED)
		return -1;

	if((read = ::recv(m_fd, buf, length, 0)) < 0)
	{
		if(errno == EWOULDBLOCK || errno == EAGAIN)
		{
			m_ioSocketState = m_outputBuffer.empty() ? IOSOCKSTAT_IDLE : IOSOCKSTAT_BUFFERING;

			m_rbuf = guestbuf;
			m_rsize = length;

			return -2;
		}

		return -1;
	}

	if(read && emu_memory_write_block(m_memory, guestbuf, buf, read) < 0)
			return -1;
	
	return read;
}

int EmulatorSocket::write(const uint8_t * buffer, size_t length)
{
	int written;

	if(m_state != SS_CONNECTED)
		return -1;

	if((written = send(m_fd, buffer, length, 0)) < (int) length)
	{
		if(!written)
			return 0;
		else if(written < 0)
		{
			if(errno != EWOULDBLOCK && errno != EAGAIN)
				return -1;

			written = 0;
		}

		m_outputBuffer.append(buffer + written, (int) length - written);
		m_ioSocketState = IOSOCKSTAT_BUFFERING;
		m_wsize = length - (size_t) written;

		return -2;
	}

	return length;
}

int EmulatorSocket::connect(uint32_t address, uint16_t port)
{
	struct sockaddr_in addr;

	addr.sin_addr.s_addr = address;
	addr.sin_port = port;
	addr.sin_family = AF_INET;

	int res = ::connect(m_fd, (struct sockaddr *) &addr, sizeof(addr));

	if(res < 0)
	{
		if(!(errno == EAGAIN || errno == EINPROGRESS))
			return -1;

		m_state = SS_CONNECTING;
		m_ioSocketState = IOSOCKSTAT_IDLE;

		return -2;
	}

	m_state = SS_CONNECTED;

	return res;
}

int EmulatorSocket::bind(uint32_t address, uint16_t port)
{
	struct sockaddr_in addr;
	uint32_t effectiveAddress;

	if(!inet_aton(m_session->getRecorder()->getDestination().name.c_str(), (struct in_addr *) &effectiveAddress))
		return -1;

	if(address != INADDR_ANY && address != effectiveAddress)
	{
		char buf[16];

		strcpy(buf, inet_ntoa(* (struct in_addr *) &address));
		GLOG(L_INFO, "Shellcode of %p tried to bind %s, but attack went to %s!", m_session->getRecorder(),
			buf, inet_ntoa(* (struct in_addr *) &effectiveAddress));
	}

	addr.sin_addr.s_addr = effectiveAddress;
	addr.sin_port = port;
	addr.sin_family = AF_INET;

	return ::bind(m_fd, (struct sockaddr *) &addr, sizeof(addr));
}

int EmulatorSocket::listen(uint32_t backlog)
{
	m_state = SS_LISTENING;
	return ::listen(m_fd, backlog);
}

int EmulatorSocket::accept(uint32_t guestbuf, uint32_t length)
{
	if(length > 64)
		length = 64;

	uint8_t buf[length];
	int res;
	

	if((res = ::accept(m_fd, guestbuf ? (struct sockaddr *) buf : 0, guestbuf ? &length : 0)) < 0)
	{
		if(errno == EWOULDBLOCK || errno == EAGAIN)
		{
			m_ioSocketState = IOSOCKSTAT_IDLE;

			m_rbuf = guestbuf;
			m_rsize = length;
	
			return -2;
		}

		return -1;
	}

	if(guestbuf)
	{
		if(emu_memory_write_block(m_memory, guestbuf, buf, length) < 0)
			return -1;
	}

	return m_session->registerSocket(new EmulatorSocket(res, m_session, m_memory));
}
