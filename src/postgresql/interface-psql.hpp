/*
 *				    _ _           _      _ 
 *	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
 *	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
 *	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
 *	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
 *
 *
 * 	Copyright 2010 Georg Wicherski, Kaspersky Labs GmbH
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


#ifndef __MWCOLLECTD_EMBEDPYTHON_HPP
#define __MWCOLLECTD_EMBEDPYTHON_HPP

#include <Daemon.hpp>
using namespace mwcollectd;


#include <stdint.h>
#include <arpa/inet.h>

#include <string>
#include <queue>

#include <libpq-fe.h>


typedef vector<vector<string> > QueryResult;

class SqlRequestHandler
{
public:
	virtual ~SqlRequestHandler() { }
	
	virtual void queryCompleted(bool success, QueryResult * result,
		bool binaryResult) { }
	
	virtual void prepareCompleted(string name, bool success) { }
	
	virtual void notifyArrived(string name) { }
};



struct SqlParameter
{
	SqlParameter()
	{
		isNull = false;
		isBinary = false;
	}

	SqlParameter(uint32_t i)
	{
		i = htonl(i);
		isNull = false;
		isBinary = true;
		value = string((char *) &i, sizeof(i));
	}
	
	SqlParameter(string s, bool binary = true)
	{
		isNull = false;
		isBinary = binary;
		value = s;
	}

	bool isNull, isBinary;
	string value;
};

#define PSQL_CONV32(a) (ntohl(a))
#define PSQL_CONV16(a) (ntohs(a))

class InterfacePostgres;

class PostgresSocket : public IOSocket
{
public:
	PostgresSocket(Daemon * daemon, Configuration * config, string address,	
		InterfacePostgres * parent);
	
	virtual void pollRead();
	virtual void pollWrite();
	virtual void pollError();
	
	inline int getSocket() { return PQsocket(m_connection); }
	
	void sendQuery(string query, SqlRequestHandler * handler);
	void sendPreparedQuery(string name, list<SqlParameter>& parameters,
		bool binaryResult, SqlRequestHandler * handler);
	void sendPreparedQuery(string name, bool binaryResult,
		SqlRequestHandler * handler);
	void prepareStatement(string name, string query,
		SqlRequestHandler * handler);
		
	string escapeString(string input);
	
	void closeConnection();
	
	inline void setNotifyHandler(SqlRequestHandler * handler)
	{ m_notifyHandler = handler; }

protected:
	void transcodeResult(QueryResult& qresult, PGresult * pgresult);
	
	void emitPreparedQuery(string name, list<SqlParameter>& parameters,
		bool binaryResult);
		
private:
	PGconn * m_connection;
	Daemon * m_daemon;
	bool m_connected;
	InterfacePostgres * m_parent;
	
	enum RequestType
	{
		RT_QUERY_SIMPLE,
		RT_QUERY_PREPARED,
		RT_PREPARE,
	};
	
	struct RequestCache
	{
		RequestType type;
		
		string query;
				
		struct
		{
			list<SqlParameter> parameters;
			bool resultBinary;
		} prepared;
		
		struct
		{
			string name;
		} prepare;
		
		SqlRequestHandler * handler;
	};
	
	SqlRequestHandler * m_notifyHandler;
	
	list<RequestCache> m_queue;
};



class InterfacePostgres : public Module, public NameResolver,
	public SqlRequestHandler, public EventSubscriber, public TimeoutReceiver
{
public:
	InterfacePostgres(Daemon * daemon);
	virtual ~InterfacePostgres() { }
	
	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();
	
	virtual const char * getName() { return "postgresql"; }
	virtual const char * getDescription() { return "Connect mwcollectd asynchronously "
		"to a PostgreSQL server, exporting a query interface via Events."; }
	virtual void nameResolved(string name, list<string> addresses,
		NameResolutionStatus status);
		
	void connectionDead(PostgresSocket * socket);
	
	virtual void handleEvent(Event * firedEvent);
	
	
	virtual void queryCompleted(bool success, QueryResult * result,
		bool binary);
	virtual void prepareCompleted(string name, bool success);
	virtual void notifyArrived(string name);

	
	virtual void timeoutFired(Timeout timeout);

	
private:
	Configuration * m_config;
	Daemon * m_daemon;
	PostgresSocket * m_socket;
	
	bool m_initialReleaseSent;
	
	uint32_t m_droneId;
	string m_host;
	
	struct TaskInfo
	{
		TaskInfo(string m, string i) :
			module(m), id(i)
		{ }

		string module;
		string id;
	};
	
	queue<TaskInfo> m_taskQueue;
	
	Timeout m_reconnectTimeout;
	
	bool m_unloading;
};


extern Daemon * g_daemon;


#endif // __MWCOLLECTD_EMBEDPYTHON_HPP
