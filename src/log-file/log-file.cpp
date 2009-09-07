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


LogFileModule::LogFileModule(Daemon * daemon)
{
	m_daemon = daemon;
	m_logFile = 0;
}

bool LogFileModule::start(Configuration * moduleConfiguration)
{
	m_filename = PREFIX "/var/log/mwcollectd/mwcollectd.log";

	if(moduleConfiguration)
		m_filename = moduleConfiguration->getString(":filename", m_filename.c_str());

	int fd = open(m_filename.c_str(), O_APPEND | O_CREAT | O_NOFOLLOW | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);

	if(fd < 0)
	{
		LOG(L_CRIT, "Could not open '%s': %s", m_filename.c_str(), strerror(errno));
		return false;
	}

	if(fcntl(fd, F_SETFL, O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_WRONLY) < 0)
	{
		LOG(L_CRIT, "Could not make '%s' non-blocking: %s", m_filename.c_str(), strerror(errno));
		return false;
	}
			
	m_logFile = new LogFile(fd, m_daemon);
	m_daemon->getNetworkManager()->addSocket(m_logFile, fd);

	m_daemon->getLogManager()->addLogFacility(this);


	return true;
}

bool LogFileModule::stop()
{
	if(!m_logFile->stop())
		return false;

	delete m_logFile;
	m_daemon->getLogManager()->removeLogFacility(this);

	return true;
}

void LogFileModule::logMessage(LogManager::LogLevel lvl,
	const char * renderedMessage)
{
	struct tm localTime;
	time_t now = time(0);
	static const char * levels[] = {
		"EVENT", "SPAM", "INFO", "CRIT"
	};
	const char * level;
	char * message;
	unsigned int msglen;

	if((size_t) lvl >= sizeof(levels) / sizeof(char *))
		return;
	
	level = levels[(size_t) lvl];

	localtime_r(&now, &localTime);

	msglen = asprintf(&message, "[%04d-%02d-%02d %02d:%02d:%02d %5s] %s\n",
		localTime.tm_year + 1900, localTime.tm_mon + 1,
		localTime.tm_mday,localTime.tm_hour, localTime.tm_min,
		localTime.tm_sec, level, renderedMessage);

	if(msglen > 0)
	{
		m_logFile->log(message, msglen);
		free(message);
	}
}

EXPORT_LIBNETWORKD_MODULE(LogFileModule, Daemon *);

