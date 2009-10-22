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

#include "download-curl.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


Daemon * g_daemon;

DownloadCurlModule::DownloadCurlModule(Daemon * daemon)
{
	m_daemon = daemon;
	g_daemon = daemon;
	m_refcount = 0;
}


bool DownloadCurlModule::start(Configuration * moduleConfiguration)
{
	m_shuttingDown = false;
	return m_daemon->getEventManager()->subscribeEventMask("shellcode.download", this);
}

void DownloadCurlModule::handleEvent(Event * event)
{
	const string& url = * (* event)["url"];

	if(strncmp("http://", url.c_str(), 7) && strncmp("https://", url.c_str(), 8) && strncmp("ftp://", url.c_str(), 6))
		return;

	++m_refcount;

	TransferSession * socket = new TransferSession(m_daemon, this, (StreamRecorder *) (* event)["recorder"].getPointerValue());
	socket->setUrl(url);
	socket->initiate();
}

bool DownloadCurlModule::stop()
{
	m_shuttingDown = true;

	if(m_refcount)
		return false;

	m_daemon->getEventManager()->unsubscribeEventMask("shellcode.download", this);
	return true;
}

void DownloadCurlModule::transferFailed(TransferSession * socket)
{
	m_daemon->getNetworkManager()->removeSocket(socket);
	delete socket;
	
	if(!--m_refcount && m_shuttingDown)
		m_daemon->stop();

}

void DownloadCurlModule::transferSucceeded(TransferSession * socket,
	const string& response)
{
	{
		Event ev = Event("shellcode.file");

		socket->getRecorder()->setProperty(("file:" + socket->getFilename()).c_str(), response);

		ev["recorder"] = (void *) socket->getRecorder();
		ev["name"] =  socket->getFilename();

		m_daemon->getEventManager()->fireEvent(&ev);
	}

	m_daemon->getNetworkManager()->removeSocket(socket);
	delete socket;

	if(!--m_refcount && m_shuttingDown)
		m_daemon->stop();

}

EXPORT_LIBNETWORKD_MODULE(DownloadCurlModule, Daemon *);

