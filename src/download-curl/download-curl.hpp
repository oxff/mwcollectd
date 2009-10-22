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


class DownloadCurlModule;

class TransferSession : public IOSocket
{
public:	
	TransferSession(Daemon * daemon, DownloadCurlModule * handler, StreamRecorder * recorder);
	~TransferSession();
	
	virtual void pollRead();
	virtual void pollWrite();
	virtual void pollError();
	
	bool initiate();
	void addPostField(string name, string value);
	void abort();

	inline StreamRecorder * getRecorder() const { return m_recorder; }
	
	inline void setUrl(const string& url) { m_url = url; }
	inline void setUserAgent(string ua) { m_userAgent = ua; }
	inline const string& getUrl() const { return m_url; }
	inline string getFilename() const { return m_url.substr(m_url.find('/', 9)); }

protected:	
	static size_t readData(void *buffer, size_t size, size_t n, void *data);
	
	int getSocket();
	bool wantSend();

private:
	CURL * m_curlHandle;
	CURLM * m_multiHandle;
	curl_httppost * m_postInfo, * m_postInfoLast;
	
	string m_buffer;
	
	Daemon * m_daemon;
	DownloadCurlModule * m_handler;

	StreamRecorder * m_recorder;
	
private:
	string m_url, m_userAgent;
};



class DownloadCurlModule : public Module, public EventSubscriber
{
public:
	DownloadCurlModule(Daemon * daemon);
	virtual ~DownloadCurlModule() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "download-curl"; }
	virtual const char * getDescription() { return "Download remote "
		"files via the HTTP(S) / FTP protocol."; }
	virtual void handleEvent(Event * event);

protected:
	virtual void transferSucceeded(TransferSession * transfer,
		const string& response);
	virtual void transferFailed(TransferSession * transfer);

	friend class TransferSession;

private:
	Daemon * m_daemon;

	string m_directory;
	size_t m_refcount;
	bool m_shuttingDown;
};

extern Daemon * g_daemon;


#endif // __MWCOLLECTD_DOWNLOADCURL_HPP
