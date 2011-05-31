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

#include "filestore-streams.hpp"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sstream>

using namespace std;


FileStoreStreamsModule::FileStoreStreamsModule(Daemon * daemon)
{
	m_daemon = daemon;
}


bool FileStoreStreamsModule::start(Configuration * moduleConfiguration)
{
	struct stat dir;

	m_filename = PREFIX "/var/log/mwcollectd/streams.log";

	if(moduleConfiguration)
	{
		m_filename = moduleConfiguration->getString(":logfile", m_filename.c_str());
		m_incomingOnly = (bool) moduleConfiguration->getInteger(":incoming-only", 0);
	}

	if(stat(m_filename.c_str(), &dir) >= 0 && !(dir.st_mode & S_IFREG))
	{
		LOG(L_CRIT, "\"%s\" does exist and is not a regular file!", m_filename.c_str());
		return false;
	}

	return m_daemon->getEventManager()->subscribeEventMask("stream.finished", this);
}

void FileStoreStreamsModule::handleEvent(Event * event)
{
	if(event->getName() == "stream.finished")
	{
		StreamRecorder * recorder = (StreamRecorder *)
			(* event)["recorder"].getPointerValue();
		int fd;

		for(StreamRecorder::Direction k = StreamRecorder::DIR_INCOMING;; k = StreamRecorder::DIR_OUTGOING)
		{
			recorder->acquireStreamData(k);
			const basic_string<uint8_t>& data =
				recorder->getStreamData(k);
			stringstream prefix;

			prefix << recorder->getSource().name << ':' << recorder->getSource().port
				<< " -> " << recorder->getDestination().name << ':' << recorder->getDestination().port
				<< (k == StreamRecorder::DIR_INCOMING ? " (in) -- " : " (out) -- ");

			if((fd = open(m_filename.c_str(), O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP)) < 0)
			{
				LOG(L_CRIT, "Could not open %s for storing stream `%s': %s", m_filename.c_str(),
					prefix.str().c_str(), strerror(errno));
				recorder->releaseStreamData(k);
				return;
			}

			int ret;
			basic_string<uint8_t>::size_type offset = 0;

			{
				const string& prefix_str = prefix.str();

				while(offset < prefix_str.size() && (ret = write(fd, prefix_str.data() + offset, prefix_str.size() - offset)) > 0)
					offset += ret;

				if(offset < prefix_str.size())
					goto write_err;
			}

			if(writeBase64(fd, data.data(), data.size()) < data.size())
				goto write_err;

			if(write(fd, "\n", 1) < 1)
			{
			write_err:
				LOG(L_CRIT, "Could not write all data of `%s' to %s: %s", prefix.str().c_str(),
					m_filename.c_str(), strerror(errno));

				recorder->releaseStreamData(k);
				close(fd);
				return;
			}

			recorder->releaseStreamData(k);
			close(fd);

			if(m_incomingOnly || k == StreamRecorder::DIR_OUTGOING)
				break;
		}
	}
}


/* derived from http://base64.sourceforge.net/b64.c */
static inline void _encode_b64_block(const uint8_t * in, char * out, size_t length)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	out[0] = alphabet[ in[0] >> 2 ];
	out[1] = alphabet[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (length > 1 ? alphabet[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (length > 2 ? alphabet[ in[2] & 0x3f ] : '=');
}

size_t FileStoreStreamsModule::writeBase64(int fd, const uint8_t * buffer, size_t bufferSize)
{
	char conversion[1024];
	size_t i, j;

	for(j = 0, i = 0; i < bufferSize; i += 3)
	{
		_encode_b64_block(&buffer[i], &conversion[j], bufferSize - i);
		j += 4;

		if(j == sizeof(conversion))
		{
			if(write(fd, conversion, j) < (int) j)
				return i - (sizeof(conversion) / 4) * 3;

			j = 0;
		}
	}

	if(j > 0)
	{
		if(write(fd, conversion, j) < (int) j)
				return i - (j / 4) * 3;
	}

	return i;
}


bool FileStoreStreamsModule::stop()
{
	m_daemon->getEventManager()->unsubscribeEventMask("stream.finished", this);
	return true;
}

EXPORT_LIBNETWORKD_MODULE(FileStoreStreamsModule, Daemon *);

