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

	m_curlTimeout = TIMEOUT_EMPTY;
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
		m_shellcodeUserAgent = "Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1)";

		LOG(L_INFO, "No configuration for download-curl module, assuming default minimum speed of 4 KiB/s measured over 60s intervals.");
	}
	else
	{
		m_measurementInterval = moduleConfiguration->getInteger(":measurement-interval", 60);
		m_minimumSpeed = moduleConfiguration->getInteger(":minimum-speed", 4096);
		m_shellcodeUserAgent = moduleConfiguration->getString(":shellcode-ua", "Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1)");
	}

	if(m_daemon->getEventManager()->subscribeEventMask("shellcode.download", this)
		&& m_daemon->getEventManager()->subscribeEventMask("download.request", this))
	{
		LOG(L_INFO, "download-curl with %s ready.", curl_version());
		return true;
	}

	return false;
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
		transfer->recorder = (StreamRecorder *) (* event)["recorder"].getPointerValue();
		transfer->recorder->acquire();

		CURL * easy = curl_easy_init();

		curl_easy_setopt(easy, CURLOPT_URL, transfer->url.c_str());
		curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, curlWriteCallback);
		curl_easy_setopt(easy, CURLOPT_WRITEDATA, transfer);
		curl_easy_setopt(easy, CURLOPT_PRIVATE, transfer);
		curl_easy_setopt(easy, CURLOPT_FILETIME, 1L);
		curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, m_minimumSpeed);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, m_measurementInterval);
		curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(easy, CURLOPT_INTERFACE, transfer->recorder->getDestination().name.c_str()); 
		curl_easy_setopt(easy, CURLOPT_USERAGENT, m_shellcodeUserAgent.c_str());

		curl_multi_add_handle(m_curlMulti, easy);		
		++m_refcount;
	}
	else if(* (* event) == "download.request")
	{
		Transfer * transfer = new Transfer(Transfer::TT_GENERIC);
		transfer->url = * (* event)["url"];
		transfer->usertype = * (* event)["type"];

		CURL * easy = curl_easy_init();
		
		curl_easy_setopt(easy, CURLOPT_URL, transfer->url.c_str());
		curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, curlWriteCallback);
		curl_easy_setopt(easy, CURLOPT_WRITEDATA, transfer);
		curl_easy_setopt(easy, CURLOPT_PRIVATE, transfer);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, m_minimumSpeed);
		curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, m_measurementInterval);
		curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);

		if(event->hasAttribute("ua"))
			curl_easy_setopt(easy, CURLOPT_USERAGENT, (* (* event)["ua"]).c_str());

		if(event->hasAttribute("ssl-verify") && (* event)["ssl-verify"].getIntegerValue())
			curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
		else
			curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
		
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
						CURLFORM_CONTENTSLENGTH, (* (* event)["post:" + field]).size(),
						CURLFORM_END);
				}
				
				fields.erase(0, delim + 1);
			}

			if(!fields.empty())
			{
				curl_formadd(&post, &lastpost, CURLFORM_COPYNAME, fields.c_str(),
					CURLFORM_COPYCONTENTS, (* (* event)["post:" + fields]).data(),
					CURLFORM_CONTENTSLENGTH, (* (* event)["post:" + fields]).size(),
					CURLFORM_END);
			}

			if(post)
				curl_easy_setopt(easy, CURLOPT_HTTPPOST, post);
		}

		if(event->hasAttribute("opaque"))
			transfer->opaque = (* event)["opaque"].getPointerValue();
		else
			transfer->opaque = 0;
		
		curl_multi_add_handle(m_curlMulti, easy);
		++m_refcount;
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

int DownloadCurlModule::curlWriteCallback(void * data, size_t block, size_t nblocks, Transfer * transfer)
{
	transfer->buffer.append((char *) data, block * nblocks);
	return block * nblocks;
}

void DownloadCurlModule::checkFinished(int remaining)
{
	CURL * easy;
	CURLcode result;
	CURLMsg * message;
	int messagesLeft;
	Transfer * transfer;

	if((size_t) remaining == m_refcount)
		return;

	m_refcount = (size_t) remaining;

	do
	{
		easy = 0;

		do
		{
			message = curl_multi_info_read(m_curlMulti, &messagesLeft);

			if(message && message->msg == CURLMSG_DONE)
			{
				easy = message->easy_handle;
				result = message->data.result;

				break;
			}
		} while(messagesLeft);

		if(!easy)
			break;

		curl_easy_getinfo(easy, CURLINFO_PRIVATE, &transfer);

		if(result == CURLE_OK)
		{
			switch(transfer->type)
			{
				case Transfer::TT_GENERIC:
				{
					const char * effectiveUrl = 0;
					Event ev = Event("download.result.success");

					ev["type"] = transfer->usertype;
					ev["url"] = transfer->url;
					ev["response"] = transfer->buffer;

					if(transfer->opaque)
						ev["opaque"] = transfer->opaque;
					
					if(curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &effectiveUrl) == CURLE_OK && effectiveUrl)
						ev["effective-url"] = effectiveUrl;

					m_daemon->getEventManager()->fireEvent(&ev);
					break;
				}

				case Transfer::TT_SHELLCODE:
				{
					string filename = transfer->url.substr(transfer->url.rfind('/') + 1);
					Event ev = Event("shellcode.file");
					const char * effectiveUrl = 0, * primaryAddress = 0;
					long filetime = 0, responseCode = 0;

					transfer->recorder->setProperty(("file:" + filename).c_str(), transfer->buffer);
					transfer->recorder->setProperty(("url:" + filename).c_str(), transfer->url);
			
					if(curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &effectiveUrl) == CURLE_OK && effectiveUrl)
						transfer->recorder->setProperty(("effective-url:" + filename).c_str(), effectiveUrl);
					
					if(curl_easy_getinfo(easy, CURLINFO_PRIMARY_IP, &primaryAddress) == CURLE_OK && primaryAddress)
						transfer->recorder->setProperty(("ip:" + filename).c_str(), primaryAddress);
					
					if(curl_easy_getinfo(easy, CURLINFO_FILETIME, &filetime) == CURLE_OK && filetime > 0)
					{
						char timebuf[32];
						
						sprintf(timebuf, "%lu", filetime);
						transfer->recorder->setProperty(("filetime:" + filename).c_str(), timebuf);
					}
			
					if(curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &responseCode) == CURLE_OK && responseCode)
					{
						if(responseCode < 200 || responseCode >= 300)
						{
							LOG(L_SPAM, "Discarding shellcode download from %s due to code %u.", transfer->url.c_str(), responseCode);
							transfer->recorder->release();
							break;
						}
					}

					ev["recorder"] = (void *) transfer->recorder;
					ev["name"] = filename;
					ev["url"] = transfer->url;

					transfer->recorder->release();

					m_daemon->getEventManager()->fireEvent(&ev);
					break;
				}
			}
		}
		else if(transfer->type == Transfer::TT_GENERIC)
		{
			long responseCode = 0;
			char * effectiveUrl = 0;
			Event ev = Event("download.result.failure");

			if(transfer->opaque)
				ev["opaque"] = transfer->opaque;

			if(curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &effectiveUrl) == CURLE_OK && effectiveUrl)
				ev["effective-url"] = string(effectiveUrl);
			
			if(curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &responseCode) == CURLE_OK && responseCode)
				ev["code"] = responseCode;

			ev["type"] = transfer->usertype;
			ev["url"] = transfer->url;

			m_daemon->getEventManager()->fireEvent(&ev);
		}
		else
		{
			LOG(L_SPAM, "Shellcode initiated transfer of %s for %p failed: %s",
				transfer->url.c_str(), transfer->recorder, curl_easy_strerror(result));
			transfer->recorder->release();
		}

		curl_multi_remove_handle(m_curlMulti, easy);
		curl_easy_cleanup(easy);
		delete transfer;
	} while(messagesLeft);

	if(!m_refcount && m_shuttingDown)
		g_daemon->stop();
}



EXPORT_LIBNETWORKD_MODULE(DownloadCurlModule, Daemon *);

