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


#ifndef __MWCOLLECTD_DOWNLOADTFTP_HPP
#define __MWCOLLECTD_DOWNLOADTFTP_HPP

#include <mwcollectd.hpp>
using namespace mwcollectd;


class DownloadTftpModule;

class TftpSocket : public IOSocket, TimeoutReceiver
{
public:
	TftpSocket(DownloadTftpModule * parent, uint32_t address, const string& filename)
		: m_socket(-1)
	{ m_address = address; m_filename = filename; m_ioSocketState = IOSOCKSTAT_IGNORE;
		m_parent = parent; m_timeout = TIMEOUT_EMPTY; }
	virtual ~TftpSocket();

	bool sendRequest();

	virtual void pollRead();
	virtual void pollWrite() { }
	virtual void pollError();

	virtual void timeoutFired(Timeout to);

	inline int getSocket() const
	{ return m_socket; }

protected:
	void sendAck();

private:
	uint32_t m_address;
	uint16_t m_port;
	string m_filename;
	int m_socket;
	uint16_t m_ackId;
	DownloadTftpModule * m_parent;
	string m_dataBuffer;
	Timeout m_timeout;
	size_t m_successiveTimeouts;
};

class DownloadTftpModule : public Module, public EventSubscriber
{
public:
	DownloadTftpModule(Daemon * daemon);
	virtual ~DownloadTftpModule() { }

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "download-tftp"; }
	virtual const char * getDescription() { return "Download remote "
		"files via the TFTP protocl."; }
	virtual void handleEvent(Event * event);

protected:
	void transferFailed(TftpSocket * socket);
	void transferSucceeded(TftpSocket * socket, const string& file);

	friend class TftpSocket;

private:
	Daemon * m_daemon;

	string m_directory;
	size_t m_refcount;
	bool m_shuttingDown;
};

extern Daemon * g_daemon;


#endif // __MWCOLLECTD_DOWNLOADTFTP_HPP
