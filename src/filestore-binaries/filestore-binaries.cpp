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

#include "filestore-binaries.hpp"

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


FileStoreBinariesModule::FileStoreBinariesModule(Daemon * daemon)
{
	m_daemon = daemon;
}


bool FileStoreBinariesModule::start(Configuration * moduleConfiguration)
{
	struct stat dir;

	m_directory = PREFIX "/var/log/mwcollectd/binaries/";
	m_hashType = HT_SHA2_256;

	if(moduleConfiguration)
	{
		string hashType = moduleConfiguration->getString(":type", "sha256");
		m_directory = moduleConfiguration->getString(":directory", m_directory.c_str());

		if(hashType == "sha256")
			m_hashType = HT_SHA2_256;
		else if(hashType == "sha512")
			m_hashType = HT_SHA2_512;
		else if(hashType == "md5")
			m_hashType = HT_MD5;
		else
		{
			LOG(L_CRIT, "Hash type for filestore-binaries must be 'md5', 'sha256' or 'sha512'; not '%s'!",
				hashType.c_str());

			return false;
		}
	}

	if(stat(m_directory.c_str(), &dir) < 0 || !(dir.st_mode & S_IFDIR))
	{
		LOG(L_CRIT, "\"%s\" does not exist or is not a directory!", m_directory.c_str());
		return false;
	}

	if(* (-- m_directory.end()) != '/')
		m_directory.append(1, '/');

	return m_daemon->getEventManager()->subscribeEventMask("shellcode.file", this);
}

void FileStoreBinariesModule::handleEvent(Event * event)
{
	StreamRecorder * recorder = (StreamRecorder *) (* event)["recorder"].getPointerValue();
	string name = * (* event)["name"];
	string dataref = recorder->getProperty(("file:" + name).c_str());

	uint8_t * data = new uint8_t[dataref.size()];
	memcpy(data, dataref.data(), dataref.size());

	m_queue.push_back(pair<StreamRecorder *, string>( recorder, name));	
	m_daemon->getHashManager()->computeHash(this, m_hashType, data, dataref.size());
}

void FileStoreBinariesModule::hashComputed(HashType type, uint8_t * data,
	unsigned int dataLength, uint8_t * hash, unsigned int hashLength)
{
	StreamRecorder * recorder = m_queue.front().first;
	string name = m_queue.front().second;

	char filename[hashLength * 2 + 1];

	m_queue.pop_front();

	{
		for(unsigned int k = 0; k < hashLength; ++k)
			sprintf(&filename[k << 1], "%02hx", hash[k]);

		filename[hashLength << 1] = 0;
	}

	{
		int fd;

		if((fd = open((m_directory + filename).c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP)) < 0)
		{
			LOG(L_CRIT, "Could not open %s for storing stream: %s", filename, strerror(errno));

			recorder->release();
			free(data);

			return;
		}

		int ret;
		basic_string<uint8_t>::size_type offset = 0;

		while(offset < dataLength && (ret = write(fd, data + offset, dataLength - offset)) > 0)
			offset += ret;

		if(offset < dataLength)
		{
			LOG(L_CRIT, "Could not write all data to %s: %s", filename, strerror(errno));

			close(fd);
			recorder->release();
			free(data);

			return;
		}

		close(fd);
	}
	
	free(data);

	{
		int fd;

		if((fd = open((m_directory + filename + ".instances").c_str(), O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP)) < 0)
		{
			LOG(L_CRIT, "Could not open %s for storing instances: %s", filename, strerror(errno));

			recorder->release();
			return;
		}

		FILE * file = fdopen(fd, "at");

		if(file)
		{
			fprintf(file, "%s:%hu -> %s:%hu\n", recorder->getSource().name.c_str(), recorder->getSource().port,
				recorder->getDestination().name.c_str(), recorder->getDestination().port);

			vector<pair<string, string> > props = recorder->getProperties();

			for(vector<pair<string, string> >::iterator it = props.begin(); it != props.end(); ++it)
			{
				if(it->first.substr(0, 5) == "file:")
					continue;

				fprintf(file, "\t%s: %s\n", it->first.c_str(), it->second.c_str());
			}

			fclose(file);
		}
		
		close(fd);
	}

	recorder->release();
}

bool FileStoreBinariesModule::stop()
{
	m_daemon->getEventManager()->unsubscribeEventMask("shellcode.file", this);
	return true;
}

EXPORT_LIBNETWORKD_MODULE(FileStoreBinariesModule, Daemon *);

