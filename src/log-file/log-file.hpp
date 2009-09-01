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


#ifndef __MWCOLLECTD_FILESTORESTREAMS_HPP
#define __MWCOLLECTD_FILESTORESTREAMS_HPP

#include <mwcollectd.hpp>
using namespace mwcollectd;


class LogFile : public IOSocket
{
public:
	inline LogFile(int fd, Daemon * daemon)
		: m_stopping(false)
	{ m_fd = fd; m_daemon = daemon; }
	virtual ~LogFile() { }

	virtual void pollRead();
	virtual void pollWrite();
	virtual void pollError();

	void log(const char * data, size_t length);

	bool stop();

private:
	int m_fd;
	string m_buffer;

	bool m_stopping;

	Daemon * m_daemon;
};

class LogFileModule : public Module, public LogFacility
{
public:
	LogFileModule(Daemon * daemon);
	virtual ~LogFileModule() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "log-file"; }
	virtual const char * getDescription() { return "(Asynchronously)"
		" write mwcollectd logs to your filesystem."; }
	
	virtual const char * getTarget() { return m_filename.c_str(); }
	virtual void logMessage(LogManager::LogLevel level,
		const char * renderedMessage);

private:
	string m_filename;
	LogFile * m_logFile;
	Daemon * m_daemon;
};


#endif // __MWCOLLECTD_FILESTORESTREAMS_HPP
