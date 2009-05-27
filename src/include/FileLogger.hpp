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

#ifndef __MWCOLLECTD_FILELOGGER_HPP
#define __MWCOLLECTD_FILELOGGER_HPP

#include "mwcollectd.hpp"
#include <stdio.h>

class FileLogger : public LogFacility
{
public:
	FileLogger(FILE * file, bool close = false)
	{ m_file = file; m_close = close; }

	virtual ~FileLogger()
	{
		if(m_close)
			fclose(m_file);
	}
	
	virtual void logMessage(LogManager::LogLevel lvl, const char * renderedMessage)
	{
		struct tm localTime;
		time_t now = time(0);
		static const char * levels[] = {
			"EVENT", "SPAM", "INFO", "CRIT"
		};
		const char * level;

		if((size_t) lvl >= sizeof(levels) / sizeof(char *))
			return;
		
		level = levels[(size_t) lvl];

		localtime_r(&now, &localTime);

		if(m_file == stdout)
		{
			static const char * colors[] = {
				"33", "36", "32", "31;1"
			};

			fprintf(m_file, "[%04d-%02d-%02d %02d:%02d:%02d %5s] \033[%sm%s\033[0m\n",
				localTime.tm_year + 1900, localTime.tm_mon + 1,
				localTime.tm_mday,localTime.tm_hour, localTime.tm_min,
				localTime.tm_sec, level, colors[lvl], renderedMessage);
		}
		else
		{
			fprintf(m_file, "[%04d-%02d-%02d %02d:%02d:%02d %5s] %s\n",
				localTime.tm_year + 1900, localTime.tm_mon + 1,
				localTime.tm_mday,localTime.tm_hour, localTime.tm_min,
				localTime.tm_sec, level, renderedMessage);
		}
	}
	
	virtual const char * getName()
	{
		return "[builtin:console]";
	}
	
	virtual const char * getDescription()
	{
		return "Logs all log messages to the standard output.";
	}
	
	virtual const char * getTarget()
	{
		return "stdout";
	}

protected:
	FILE * m_file;
	bool m_close;
};

#endif // __MWCOLLECTD_FILELOGGER_HPP
