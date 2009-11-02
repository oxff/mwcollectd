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

#include "download-tftp.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


Daemon * g_daemon;

DownloadTftpModule::DownloadTftpModule(Daemon * daemon)
{
	m_daemon = daemon;
	g_daemon = daemon;
	m_refcount = 0;
}


bool DownloadTftpModule::start(Configuration * moduleConfiguration)
{
	m_shuttingDown = false;
	return m_daemon->getEventManager()->subscribeEventMask("shellcode.download", this);
}

void DownloadTftpModule::handleEvent(Event * event)
{
	const string& url = * (* event)["url"];
	string::const_iterator it;
	char address[16];
	struct in_addr peer;

	if(strncmp("tftp://", url.c_str(), 7))
		return;

	{
		size_t k = 0;
		it = url.begin() + 7;

		for(; k < sizeof(address) - 1 && it != url.end() && * it != '/'; ++k, ++it)
			address[k] = * it;

		if(it == url.end())
			return;

		address[k] = 0;
		++it;
	}

	if(!inet_aton(address, &peer))
	{
		LOG(L_CRIT, "Address \"%s\" in URL \"%s\" is not parseable!", address, url.c_str());
		return;
	}

	TftpSocket * socket = new TftpSocket(this, (StreamRecorder *) (* event)["recorder"].getPointerValue(),
		peer.s_addr, url.substr(it - url.begin()).c_str());

	if(socket->sendRequest())
	{
		++m_refcount;

		m_daemon->getNetworkManager()->addSocket(socket, socket->getSocket());
	}
	else
		delete socket;
}

bool DownloadTftpModule::stop()
{
	m_shuttingDown = true;

	if(m_refcount)
		return false;

	m_daemon->getEventManager()->unsubscribeEventMask("shellcode.download", this);
	return true;
}

void DownloadTftpModule::transferFailed(TftpSocket * socket)
{
	if(!--m_refcount && m_shuttingDown)
		m_daemon->stop();

	m_daemon->getNetworkManager()->removeSocket(socket);
	delete socket;
}

void DownloadTftpModule::transferSucceeded(TftpSocket * socket, const string& file)
{
	{
		Event ev = Event("shellcode.file");

		socket->getRecorder()->setProperty(("file:" + socket->getFilename()).c_str(), file);

		ev["recorder"] = (void *) socket->getRecorder();
		ev["name"] = socket->getFilename();
		ev["url"] = socket->getUrl();

		m_daemon->getEventManager()->fireEvent(&ev);
	}

	if(!--m_refcount && m_shuttingDown)
		m_daemon->stop();

	m_daemon->getNetworkManager()->removeSocket(socket);
	delete socket;
}

EXPORT_LIBNETWORKD_MODULE(DownloadTftpModule, Daemon *);

