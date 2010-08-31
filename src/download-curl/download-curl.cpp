/*
 *				    _ _           _      _ 
 *	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
 *	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
 *	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
 *	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
 *
 *
 * 	Copyright 2009-2010 Georg Wicherski, Kaspersky Labs GmbH
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
DownloadCurlModule * g_module;

DownloadCurlModule::DownloadCurlModule(Daemon * daemon)
{
	m_daemon = daemon;
	g_daemon = daemon;
	m_refcount = 0;

	m_curlMulti = curl_multi_init();
	curl_multi_setopt(m_curlMulti, CURLMOPT_SOCKETFUNCTION, (curl_socket_callback) curlSocketCallback);
	curl_multi_setopt(m_curlMulti, CURLMOPT_SOCKETDATA, this);
	curl_multi_setopt(m_curlMulti, CURLMOPT_TIMERFUNCTION, (curl_multi_timer_callback) curlTimeoutCallback);
	curl_multi_setopt(m_curlMulti, CURLMOPT_TIMERDATA, this);
}

DownloadCurlModule::~DownloadCurlModule()
{
	curl_multi_cleanup(m_curlMulti);
}


bool DownloadCurlModule::start(Configuration * moduleConfiguration)
{
	if(g_module)
		return false;

	g_module = this;
	m_shuttingDown = false;

	if(!moduleConfiguration)
	{
		m_measurementInterval = 60;
		m_minimumSpeed = 4096;

		LOG(L_INFO, "No configuration for download-curl module, assuming default minimum speed of 4 KiB/s measured over 60s intervals.");
	}
	else
	{
		m_measurementInterval = moduleConfiguration->getInteger(":measurement-interval", 60);
		m_minimumSpeed = moduleConfiguration->getInteger(":minimum-speed", 4096);
	}

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

		Transfer * transfer = new Transfer(Transfer::TT_SHELLCODE);
		transfer->url = url;

		CURL * easy = curl_easy_init();

		curl_easy_setopt(easy, CURLOPT_URL, transfer->url.c_str());
		curl_easy_setopt(easy, CURLOPT_PRIVATE, transfer);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, m_minimumSpeed);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, m_measurementInterval);

		curl_multi_add_handle(m_curlMulti, easy);
		++m_refcount;

		// TODO FIXME: perform until really added
	}
	else if(* (* event) == "download.request")
	{
		++m_refcount;

		Transfer * transfer = new Transfer(Transfer::TT_GENERIC);
		transfer->url = * (* event)["url"];

		CURL * easy = curl_easy_init();
		
		curl_easy_setopt(easy, CURLOPT_URL, transfer->url.c_str());
		curl_easy_setopt(easy, CURLOPT_PRIVATE, transfer);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, m_minimumSpeed);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, m_measurementInterval);

		if(event->hasAttribute("ua"))
			curl_easy_setopt(easy, CURLOPT_USERAGENT, (* (* event)["ua"]).c_str());
		
		if(event->hasAttribute("postfields"))
		{
			string fields = * (* event)["postfields"];
			string::size_type delim;
			struct curl_httppost * post = 0, * lastpost = 0;

			while((delim = fields.find(',')) != string::npos)
			{
				string field = fields.substr(0, delim);

				if(!field.empty())
				{
					curl_formadd(&post, &lastpost, CURLFORM_COPYNAME, field.c_str(),
						CURLFORM_COPYCONTENTS, (* (* event)["post:" + field]).data(),
						CURLFORM_CONTENTSLENGTH, (* (* event)["post:" + field]).size());
				}
				
				fields.erase(0, delim + 1);
			}

			if(!fields.empty())
			{
				curl_formadd(&post, &lastpost, CURLFORM_COPYNAME, fields.c_str(),
					CURLFORM_COPYCONTENTS, (* (* event)["post:" + fields]).data(),
					CURLFORM_CONTENTSLENGTH, (* (* event)["post:" + fields]).size());
			}

			if(post)
				curl_easy_setopt(easy, CURLOPT_HTTPPOST, post);
		}

		if(event->hasAttribute("opaque"))
			transfer->opaque = (* event)["opaque"].getPointerValue();
		
		curl_multi_add_handle(m_curlMulti, easy);
		++m_refcount;

		// TODO FIXME: perform until really added
	}
}

bool DownloadCurlModule::stop()
{
	m_shuttingDown = true;

	m_daemon->getEventManager()->unsubscribeEventMask("shellcode.download", this);
	m_daemon->getEventManager()->unsubscribeEventMask("download.request", this);

	if(m_refcount)
		return false;

	g_module = 0;
	return true;
}


int DownloadCurlModule::curlSocketCallback(CURL * easy, curl_socket_t s, int action, DownloadCurlModule * module, CurlSocket * socket)
{
	return module->socketCallback(easy, s, action, socket);
}

int DownloadCurlModule::socketCallback(CURL * easy, curl_socket_t s, int action, CurlSocket * socket)
{
	if(action == CURL_POLL_REMOVE)
	{
		m_daemon->getNetworkManager()->removeSocket(socket);
		delete socket;

		return 0;
	}

	if(!socket)
	{
		socket = new CurlSocket(s);
		m_daemon->getNetworkManager()->addSocket(socket, s);

		curl_multi_assign(m_curlMulti, s, socket);
	}

	switch(action)
	{
		default:
		case CURL_POLL_NONE:
			socket->m_ioSocketState = IOSOCKSTAT_IGNORE;
			break;

		case CURL_POLL_IN:
			socket->m_ioSocketState = IOSOCKSTAT_IDLE;
			break;

		case CURL_POLL_OUT:
		case CURL_POLL_INOUT:
			socket->m_ioSocketState = IOSOCKSTAT_BUFFERING;
			break;
	}

	return 0;
}

int DownloadCurlModule::curlTimeoutCallback(CURLM * multi, long timeout, DownloadCurlModule * module)
{
	if(module->m_curlTimeout != TIMEOUT_EMPTY)
		module->m_daemon->getTimeoutManager()->dropTimeout(module->m_curlTimeout);

	if(timeout >= 0)
		module->m_curlTimeout = module->m_daemon->getTimeoutManager()->scheduleTimeout(timeout / 1000, module);
	else if(timeout == 0)
		module->timeoutFired(module->m_curlTimeout);
	else		
		module->m_curlTimeout = TIMEOUT_EMPTY;

	return 0;
}

void DownloadCurlModule::timeoutFired(Timeout t)
{
	if(t == m_curlTimeout)
	{
		int remainingTransfers;
		while(curl_multi_socket_action(m_curlMulti, CURL_SOCKET_TIMEOUT, 0, &remainingTransfers) == CURLM_CALL_MULTI_PERFORM);

		checkFinished(remainingTransfers);

		m_curlTimeout = TIMEOUT_EMPTY;
	}
}

void DownloadCurlModule::checkFinished(int remaining)
{
	CURL * easy;
	CURLcode result;
	CURLMsg * message;
	int messagesLeft;

	if((size_t) remaining == m_refcount)
		return;

	m_refcount = (size_t) remaining;

	do
	{
		easy = 0;

		do
		{
			message = curl_multi_info_read(m_curlMulti, &messagesLeft);

			if(message->msg == CURLMSG_DONE)
			{
				easy = message->easy_handle;
				result = message->data.result;

				break;
			}
		} while(messagesLeft);

		if(!easy)
			break;

		// TODO: process transfer here

		curl_multi_remove_handle(m_curlMulti, easy);
		curl_easy_cleanup(easy);
	} while(messagesLeft);
}

#if 0
void DownloadCurlModule::transferFailed(TransferSession * socket)
{
	if(socket->getType() == socket->ST_GENERIC)
	{
		DEvent ev = Event("download.result.failure");

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
			ev["name"] = socket->getFilename();
			ev["url"] = socket->getUrl();

			if(socket->getOpaque())
				ev["opaque"] = socket->getOpaque();

			m_daemon->getEventManager()->fireEvent(&ev);
			break;
		}

		case TransferSession::ST_GENERIC:
		{
			Event ev = Event("download.result.success");

			ev["type"] = socket->getTypeName();
			ev["url"] = socket->getUrl();
			ev["response"] = response;

			if(socket->getOpaque())
				ev["opaque"] = socket->getOpaque();

			m_daemon->getEventManager()->fireEvent(&ev);
			break;
		}
	}

	m_daemon->getNetworkManager()->removeSocket(socket);
	delete socket;

	if(!--m_refcount && m_shuttingDown)
		m_daemon->stop();

}
#endif

EXPORT_LIBNETWORKD_MODULE(DownloadCurlModule, Daemon *);

