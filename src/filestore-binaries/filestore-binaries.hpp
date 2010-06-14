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


#ifndef __MWCOLLECTD_FILESTOREBINARIES_HPP
#define __MWCOLLECTD_FILESTOREBINARIES_HPP

#include <mwcollectd.hpp>
using namespace mwcollectd;

class FileStoreBinariesModule : public Module, public EventSubscriber, public HashReceiver
{
public:
	FileStoreBinariesModule(Daemon * daemon);
	virtual ~FileStoreBinariesModule() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "filestore-biniares"; }
	virtual const char * getDescription() { return "Save downloaded "
		"malware binaries in your local filesystem."; }
	virtual void handleEvent(Event * event);
	virtual void hashComputed(HashType type, uint8_t * data,
		unsigned int dataLength, uint8_t * hash, unsigned int hashLength);

private:
	Daemon * m_daemon;

	string m_directory;

	HashType m_hashType;

	list<StreamRecorder *> m_queue;
};


#endif // __MWCOLLECTD_FILESTOREBINARIES_HPP
