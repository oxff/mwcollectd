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

#include "log-file.hpp"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

using namespace std;


void LogFile::pollRead()
{
	LOG(L_CRIT, __PRETTY_FUNCTION__);
}

void LogFile::pollError()
{
	LOG(L_CRIT, __PRETTY_FUNCTION__);
}

void LogFile::pollWrite()
{
	ssize_t written = write(m_fd, m_buffer.data(), m_buffer.size());

	if(written < 0)
	{
		if(errno != EWOULDBLOCK && errno != EAGAIN)
		{
			LOG(L_CRIT, "Could not write to log file anymore: %s", strerror(errno));
			m_daemon->stop();

			return;
		}

		written = 0;
	}

	m_buffer.erase(0, written);

	if(m_buffer.empty())
		m_ioSocketState = IOSOCKSTAT_IGNORE;
}

void LogFile::log(const char * data, size_t length)
{
	if(__builtin_expect(m_stopping, false))
		return;

	if(!m_buffer.empty())
	{
		m_buffer.append(data, length);
		return;
	}

	ssize_t written = write(m_fd, data, length);

	if(written < 0)
	{
		if(errno != EWOULDBLOCK && errno != EAGAIN)
		{
			m_stopping = true;
			LOG(L_SPAM, "%s: data=%p, length=%u, m_fd=%i", __PRETTY_FUNCTION__, data, length, m_fd);
			LOG(L_CRIT, "Could not write to log file anymore: %s", strerror(errno));
			m_daemon->stop();

			return;
		}

		written = 0;
	}

	if(written < (ssize_t) length)
	{
		m_buffer.append(data + written, length - written);

		m_ioSocketState = IOSOCKSTAT_BUFFERING;
	}
}

bool LogFile::stop()
{
	m_stopping = true;

	if(!m_buffer.empty())
		return false;
	
	if(fcntl(m_fd, F_SETFL, O_APPEND | O_CREAT | O_NOFOLLOW | O_WRONLY) >= 0)
	{
		struct tm localTime;
		time_t now = time(0);
		char * message;
		unsigned int msglen;

		localtime_r(&now, &localTime);

		msglen = asprintf(&message, "-- Closing log file at [%04d-%02d-%02d %02d:%02d:%02d] ---\n",
			localTime.tm_year + 1900, localTime.tm_mon + 1,
			localTime.tm_mday,localTime.tm_hour, localTime.tm_min,
			localTime.tm_sec);

		if(msglen > 0)
		{
			ssize_t off = 0, written;

			do
			{
				written = write(m_fd, message + off, msglen);

				if(written > 0)
				{
					msglen -= written;
					off += written;
				}
			} while(written > 0 && msglen > 0);

			free(message);
		}
	}

	close(m_fd);
	return true;
}
