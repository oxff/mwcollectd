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
	return m_daemon->getEventManager()->subscribeEventMask("shellcode.download", this)
		&& m_daemon->getEventManager()->subscribeEventMask("download.request", this);
}

void DownloadCurlModule::handleEvent(Event * event)
{
	if(* (* event) == "shellcode.download")
	{
		const string& url = * (* event)["url"];

		if(strncmp("http://", url.c_str(), 7) && strncmp("https://", url.c_str(), 8) && strncmp("ftp://", url.c_str(), 6))
			return;

		++m_refcount;

		TransferSession * socket = new TransferSession(m_daemon, this, (StreamRecorder *) (* event)["recorder"].getPointerValue());
		socket->setUrl(url);
		socket->initiate();
	}
	else if(* (* event) == "download.request")
	{
		++m_refcount;

		TransferSession * socket = new TransferSession(m_daemon, this, * (* event)["type"]);
		socket->setUrl(* (* event)["url"]);

		if(event->hasAttribute("ua"))
			socket->setUserAgent(* (* event)["ua"]);
	
		if(event->hasAttribute("postfields"))
		{
			string fields = * (* event)["postfields"];
			string::size_type delim;

			while((delim = fields.find(',')) != string::npos)
			{
				string field = fields.substr(0, delim);

				if(!field.empty())
					socket->addPostField(field, * (* event)["post:" + field]);
				
				fields.erase(0, delim + 1);
			}

			if(!fields.empty())
				socket->addPostField(fields, * (* event)["post:" + fields]);
		}

		socket->initiate();
	}
}

bool DownloadCurlModule::stop()
{
	m_shuttingDown = true;

	if(m_refcount)
		return false;

	m_daemon->getEventManager()->unsubscribeEventMask("shellcode.download", this);
	m_daemon->getEventManager()->unsubscribeEventMask("download.request", this);

	return true;
}

void DownloadCurlModule::transferFailed(TransferSession * socket)
{
	if(socket->getType() == socket->ST_GENERIC)
	{
		Event ev = Event("download.result.failure");

		ev["type"] = socket->getTypeName();
		ev["url"] = socket->getUrl();

		m_daemon->getEventManager()->fireEvent(&ev);
	}

	m_daemon->getNetworkManager()->removeSocket(socket);
	delete socket;
	
	if(!--m_refcount && m_shuttingDown)
		m_daemon->stop();

}

void DownloadCurlModule::transferSucceeded(TransferSession * socket,
	const string& response)
{
	switch(socket->getType())
	{
		case TransferSession::ST_SHELLCODE:
		{
			Event ev = Event("shellcode.file");

			socket->getRecorder()->setProperty(("file:" + socket->getFilename()).c_str(), response);

			ev["recorder"] = (void *) socket->getRecorder();
			ev["name"] =  socket->getFilename();

			m_daemon->getEventManager()->fireEvent(&ev);
			break;
		}

		case TransferSession::ST_GENERIC:
		{
			Event ev = Event("download.result.success");

			ev["type"] = socket->getTypeName();
			ev["url"] = socket->getUrl();
			ev["response"] = response;

			m_daemon->getEventManager()->fireEvent(&ev);
			break;
		}
	}

	m_daemon->getNetworkManager()->removeSocket(socket);
	delete socket;

	if(!--m_refcount && m_shuttingDown)
		m_daemon->stop();

}

EXPORT_LIBNETWORKD_MODULE(DownloadCurlModule, Daemon *);

