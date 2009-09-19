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

	m_directory = PREFIX "/var/log/mwcollectd/attacks/";

	if(moduleConfiguration)
		moduleConfiguration->getString(":directory", m_directory.c_str());

	if(stat(m_directory.c_str(), &dir) < 0 || !(dir.st_mode & S_IFDIR))
	{
		LOG(L_CRIT, "\"%s\" does not exist or is not a directory!", m_directory.c_str());
		return false;
	}

	if(* (-- m_directory.end()) != '/')
		m_directory.append(1, '/');

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
			const basic_string<uint8_t>& incoming =
				recorder->getStreamData(k);
			stringstream filename;

			filename << m_directory << recorder->getSource().name << '-' << recorder->getSource().port
				<< "_to_" << recorder->getDestination().name << '-' << recorder->getDestination().port
				<< (k == StreamRecorder::DIR_INCOMING ? "_in" : "_out");

			if((fd = open(filename.str().c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP)) < 0)
			{
				LOG(L_CRIT, "Could not open %s for storing stream: %s", filename.str().c_str(), strerror(errno));
				recorder->releaseStreamData(k);
				return;
			}

			int ret;
			basic_string<uint8_t>::size_type offset = 0;

			while(offset < incoming.size() && (ret = write(fd, incoming.data() + offset, incoming.size() - offset)) > 0)
				offset += ret;

			if(offset < incoming.size())
			{
				LOG(L_CRIT, "Could not write all data to %s: %s", filename.str().c_str(), strerror(errno));

				recorder->releaseStreamData(k);
				close(fd);
				return;
			}

			recorder->releaseStreamData(k);
			close(fd);

			if(k == StreamRecorder::DIR_OUTGOING)
			{
				break;
			}
		}

		LOG(L_INFO, "Saved stream from %s:%u to %s:%u to filesystem.", recorder->getSource().name.c_str(),
			recorder->getSource().port, recorder->getDestination().name.c_str(), recorder->getDestination().port);
	}
}

bool FileStoreStreamsModule::stop()
{
	m_daemon->getEventManager()->unsubscribeEventMask("stream.finished", this);
	return true;
}

EXPORT_LIBNETWORKD_MODULE(FileStoreStreamsModule, Daemon *);

