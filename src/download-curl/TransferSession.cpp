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


TransferSession::TransferSession(Daemon * daemon, DownloadCurlModule * handler, StreamRecorder * rec)
{
	m_type = ST_SHELLCODE;

	m_daemon = daemon;
	m_handler = handler;
	m_recorder = rec;

	m_recorder->acquire();
	
	if(!(m_curlHandle = curl_easy_init()) || !(m_multiHandle = curl_multi_init()))
	{
		ASSERT(false);
	}
	
	m_timeout = m_daemon->getTimeoutManager()->scheduleTimeout(handler->getMeasurementInterval(), this);
	m_lastMeasuredOffset = 0;
	
	m_postInfo = m_postInfoLast = 0;
}

TransferSession::TransferSession(Daemon * daemon, DownloadCurlModule * handler, const string& typeName)
{
	m_type = ST_GENERIC;

	m_daemon = daemon;
	m_handler = handler;
	m_opaque = 0;

	m_typeName = typeName;
	
	if(!(m_curlHandle = curl_easy_init()) || !(m_multiHandle =
		curl_multi_init()))
	{
		ASSERT(false);
	}
	
	m_postInfo = m_postInfoLast = 0;
}

TransferSession::~TransferSession()
{
	if(m_type == ST_SHELLCODE)
		m_recorder->release();

	if(m_multiHandle)
		curl_multi_remove_handle(m_multiHandle, m_curlHandle);
	
	curl_formfree(m_postInfo);
	curl_easy_cleanup(m_curlHandle);
	
	if(m_multiHandle)
	{
		curl_multi_cleanup(m_multiHandle);
		m_multiHandle = 0;
	}
	
	m_daemon->getNetworkManager()->removeSocket(this);
	m_daemon->getTimeoutManager()->dropTimeout(m_timeout);
}

bool TransferSession::initiate()
{
	if(m_postInfo)
		curl_easy_setopt(m_curlHandle, CURLOPT_HTTPPOST, m_postInfo);

	curl_easy_setopt(m_curlHandle, CURLOPT_FORBID_REUSE, 1);
	curl_easy_setopt(m_curlHandle, CURLOPT_SSL_VERIFYHOST, false);
	curl_easy_setopt(m_curlHandle, CURLOPT_SSL_VERIFYPEER, false);
	curl_easy_setopt(m_curlHandle, CURLOPT_URL, m_url.c_str());
	curl_easy_setopt(m_curlHandle, CURLOPT_USERAGENT, m_userAgent.c_str());
	curl_easy_setopt(m_curlHandle, CURLOPT_WRITEDATA, this);
	curl_easy_setopt(m_curlHandle, CURLOPT_WRITEFUNCTION,
		TransferSession::readData);
//	curl_easy_setopt(m_curlHandle, CURLOPT_VERBOSE, 1);
	
		
	CURLMcode error;
	
	if((error = curl_multi_add_handle(m_multiHandle, m_curlHandle)))
	{
		LOG(L_CRIT, "Error adding easy to multi: %s", curl_multi_strerror(error));
		m_handler->transferFailed(this);

		return false;
	}
	
	int handles = 0;
		
	while(curl_multi_perform(m_multiHandle, &handles) ==
		CURLM_CALL_MULTI_PERFORM && handles);
	
	m_ioSocketState = (wantSend() ? IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
	m_daemon->getNetworkManager()->addSocket(this, getSocket());

	if(!wantSend())
		pollRead();

	return true;
}

void TransferSession::addPostField(string name, string value)
{
	curl_formadd(&m_postInfo, &m_postInfoLast, CURLFORM_COPYNAME,
		name.c_str(), CURLFORM_COPYCONTENTS, value.data(),
		CURLFORM_CONTENTSLENGTH, value.size(),
		CURLFORM_END);
}

size_t TransferSession::readData(void *buffer, size_t s, size_t n, void *data)
{
	((TransferSession *) data)->m_buffer.append((const char *)buffer, s * n);	
	return s * n;
}


bool TransferSession::wantSend()
{		
	fd_set readSet, writeSet, errorSet;
	int maxFd = 0;
	CURLMcode error;
	FD_ZERO(&readSet); FD_ZERO(&writeSet); FD_ZERO(&errorSet);
	
	if((error = curl_multi_fdset(m_multiHandle, &readSet, &writeSet, &errorSet,
		&maxFd)))
	{
		LOG(L_CRIT, "Obtaining write socket failed: %s\n", curl_multi_strerror(error));
		return false;
	}

	if(maxFd < 0)
		return false;

	return FD_ISSET(maxFd, &writeSet);
}

void TransferSession::pollWrite()
{
	return pollRead();
}

void TransferSession::pollError()
{
	return pollRead();
}

void TransferSession::pollRead()
{		
	int handles = 0, queued = 0;
	
	while(curl_multi_perform(m_multiHandle, &handles) ==
		CURLM_CALL_MULTI_PERFORM && handles);
	
	CURLMsg * message;
		
	while((message = curl_multi_info_read(m_multiHandle, &queued)))
	{				
		if(message->msg == CURLMSG_DONE)
		{
			m_daemon->getNetworkManager()->removeSocket(this);
			
			if(message->data.result == CURLE_OK)
				m_handler->transferSucceeded(this, m_buffer);
			else
			{
				LOG(L_INFO, "Transfer from \"%s\" failed: %s.",
					m_url.c_str(),
					curl_easy_strerror(message->data.result));

				if(!m_buffer.empty())
					m_handler->transferSucceeded(this, m_buffer);
				else
					m_handler->transferFailed(this);
			}
			
			return;
		}
	}
	
	m_ioSocketState = (wantSend() ? IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
}

void TransferSession::abort()
{
	m_daemon->getNetworkManager()->removeSocket(this);
}

int TransferSession::getSocket()
{		
	fd_set readSet, writeSet, errorSet;
	int maxFd = 0;
	CURLMcode error;
	FD_ZERO(&readSet); FD_ZERO(&writeSet); FD_ZERO(&errorSet);
	
	if((error = curl_multi_fdset(m_multiHandle, &readSet, &writeSet, &errorSet,
		&maxFd)))
	{
		LOG(L_CRIT, "Obtaining read socket failed: %s\n", curl_multi_strerror(error));
		return -1;
	}
	
	if(maxFd == -1)
		return -1;
	
	if(!FD_ISSET(maxFd, &readSet) && !FD_ISSET(maxFd, &writeSet) &&
		!FD_ISSET(maxFd, &errorSet))
	{
		LOG(L_CRIT, "maxFd not in set: %i!\n", maxFd);
		return -1;
	}
	
	return maxFd;
}

void TransferSession::timeoutFired(Timeout t)
{
	ASSERT(m_timeout == t);

	uint32_t speed = (m_buffer.size() - m_lastMeasuredOffset) / m_handler->getMeasurementInterval();

	if(speed < m_handler->getMinimumSpeed())
	{
		LOG(L_INFO, "Download of \"%s\" was too slow with %u bytes / second.", m_url.c_str(), speed);
		m_handler->transferFailed(this);

		return;
	}

	m_lastMeasuredOffset = m_buffer.size();
	m_timeout = m_daemon->getTimeoutManager()->scheduleTimeout(m_handler->getMeasurementInterval(), this);
}
