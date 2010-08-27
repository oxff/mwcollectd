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


#ifndef __MWCOLLECTD_DOWNLOADCURL_HPP
#define __MWCOLLECTD_DOWNLOADCURL_HPP

#include <mwcollectd.hpp>
using namespace mwcollectd;

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#include <string>
#include <vector>
using namespace std;


class CurlSocket : public IOSocket
{
public:
	inline CurlSocket(int fd)
		: m_fd(fd)
	{}

	virtual ~CurlSocket() { }

	virtual void pollRead();
	virtual void pollWrite();
	virtual void pollError();

private:
	int m_fd;
};

struct Transfer
{
	enum TransferType
	{
		TT_GENERIC,
		TT_SHELLCODE,
	};

	Transfer(TransferType t)
		: type(t), opaque(0)
	{ }

	TransferType type;
	string buffer;

	string url;
	void * opaque;
};

class DownloadCurlModule : public Module, public EventSubscriber, public TimeoutReceiver
{
public:
	DownloadCurlModule(Daemon * daemon);
	virtual ~DownloadCurlModule();

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "download-curl"; }
	virtual const char * getDescription() { return "Download remote "
		"files via the protocols, such as HTTP(S) & FTP."; }
	virtual void handleEvent(Event * event);

	virtual void timeoutFired(Timeout t);

	inline uint32_t getMeasurementInterval() const
	{ return m_measurementInterval; }

	inline uint32_t getMinimumSpeed() const
	{ return m_minimumSpeed; }

	inline CURLM * getCurlMulti() const
	{ return m_curlMulti; }

protected:
	int socketCallback(CURL * easy, curl_socket_t s, int action, CurlSocket * socket);
	static int curlSocketCallback(CURL * easy, curl_socket_t s, int action, DownloadCurlModule * module, CurlSocket * socket);
	static int curlTimeoutCallback(CURLM * multi, long timeout, DownloadCurlModule * module);

	void checkFinished(int remaining);
	friend class CurlSocket;

private:
	Daemon * m_daemon;

	string m_directory;
	size_t m_refcount;
	bool m_shuttingDown;

	uint32_t m_measurementInterval, m_minimumSpeed;

	CURLM * m_curlMulti;

	Timeout m_curlTimeout;
};


extern Daemon * g_daemon;
extern DownloadCurlModule * g_module;


#endif // __MWCOLLECTD_DOWNLOADCURL_HPP
