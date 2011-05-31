/*
 *				    _ _           _      _ 
 *	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
 *	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
 *	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
 *	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
 *
 *
 * 	Copyright 2009 Georg Wicherski, Kaspersky Labs GmbH
 * 	Copyright 2011 Georg Wicherski, McAfee GmbH
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

class FileStoreStreamsModule : public Module, public EventSubscriber
{
public:
	FileStoreStreamsModule(Daemon * daemon);
	virtual ~FileStoreStreamsModule() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "filestore-streams"; }
	virtual const char * getDescription() { return "Save attack stream "
		"data in your local filesystem."; }
	virtual void handleEvent(Event * event);

protected:
	size_t writeBase64(int fd, const uint8_t * buffer, size_t bufferSize);

private:
	Daemon * m_daemon;

	string m_filename;
	bool m_incomingOnly;
};


#endif // __MWCOLLECTD_FILESTORESTREAMS_HPP
