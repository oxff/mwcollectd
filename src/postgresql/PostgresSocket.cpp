/*
 *				    _ _           _      _ 
 *	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
 *	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
 *	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
 *	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
 *
 *
 * 	Copyright 2008, Georg Wicherski <gw@mwcollect.org>
 *
 *
 *	This file is now also part of mwcollectd.
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

#include "interface-psql.hpp"


PostgresSocket::PostgresSocket(Daemon * daemon, Configuration * config,
	string address, InterfacePostgres * parent)
{
	string connect;
	
	g_daemon = daemon;
	m_daemon = daemon;
	m_parent = parent;
	
	connect = "hostaddr=" + address + " dbname="
		+ config->getString(":server:database", "") + " user="
		+ config->getString(":server:user", "") + " password="
		+ config->getString(":server:passwd", "") + " port="
		+ config->getString(":server:port", "5432") + " sslmode="
		+ (config->getInteger(":server:require-ssl", 0) ? "require" : "prefer");
		
	m_connection = PQconnectStart(connect.c_str());
	
	m_ioSocketState = (PQconnectPoll(m_connection) == PGRES_POLLING_WRITING ?
		IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
	
	m_connected = false;
	
	m_notifyHandler = 0;
}

void PostgresSocket::transcodeResult(QueryResult& qresult,
	PGresult * pgresult)
{
	int rows = PQntuples(pgresult), columns = PQnfields(pgresult);
	
	qresult = QueryResult(rows);
	
	for(int i = 0; i < rows; ++i)
	{
		qresult[i] = vector<string>(columns);
		vector<string>& row = qresult[i];
		
		for(int j = 0; j < columns; ++j)
		{
			if(PQgetisnull(pgresult, i, j))
				row[j] = string();
			else
			{
				row[j] = string(PQgetvalue(pgresult, i, j),
					PQgetlength(pgresult, i, j));
			}
		}
	}
}

void PostgresSocket::pollRead()
{	
	if(!m_connected)
	{
		PostgresPollingStatusType status = PQconnectPoll(m_connection);
		
		switch(status)
		{
			case PGRES_POLLING_WRITING:
				m_ioSocketState = IOSOCKSTAT_BUFFERING;
				break;
				
			case PGRES_POLLING_READING:
				m_ioSocketState = IOSOCKSTAT_IDLE;
				break;
			
			default:
			case PGRES_POLLING_FAILED:
				return pollError();
			
			case PGRES_POLLING_OK:
				m_connected = true;
				m_ioSocketState = IOSOCKSTAT_IDLE;
				
				PQsetnonblocking(m_connection, 1);
				LOG(L_SPAM, "PostgreSQL socket connected.");
				
				pollRead();
		}
	}
	else
	{
		if(PQstatus(m_connection) != CONNECTION_OK)
			return pollError();
		
		if(!PQconsumeInput(m_connection))
			return pollError();
		
		if(!PQisBusy(m_connection))
		{
			PGresult * result;
						
			while((result = PQgetResult(m_connection)))
			{
				QueryResult qresult;
				list<RequestCache>::iterator qry = m_queue.begin();
				
				switch(qry->type)
				{
					case RT_QUERY_SIMPLE:
					case RT_QUERY_PREPARED:
					
					switch(PQresultStatus(result))
					{
						case PGRES_COMMAND_OK:
							qry->handler->queryCompleted(true, 0, false);
							break;
						
						case PGRES_TUPLES_OK:
							transcodeResult(qresult, result);
							qry->handler->queryCompleted(true, &qresult, false);
							break;
							
						default:
							qry->handler->queryCompleted(false, 0, false);
							
							printf("%s", PQerrorMessage(m_connection));
					}
					
					break;
					
					case RT_PREPARE:
					qry->handler->prepareCompleted(qry->prepare.name,
						PQresultStatus(result) == PGRES_COMMAND_OK);
					
					if(PQresultStatus(result) != PGRES_COMMAND_OK)
						printf("%s", PQerrorMessage(m_connection));
				}
				
				PQclear(result);
				
				if(!m_connection)
				{
					m_parent->connectionDead(this);
					return;
				}
				
				m_queue.pop_front();
			}
			
			if(!m_queue.empty())
			{
				list<RequestCache>::iterator qry = m_queue.begin();
				
				switch(qry->type)
				{
					case RT_QUERY_SIMPLE:
					PQsendQuery(m_connection, qry->query.c_str());
					qry->query = std::string();
					break;
					
					case RT_PREPARE:
						PQsendPrepare(m_connection, qry->prepare.name.c_str(),
							qry->query.c_str(), 0, 0);
						
						break;
					
					case RT_QUERY_PREPARED:
					emitPreparedQuery(qry->query, qry->prepared.parameters,
						qry->prepared.resultBinary);
					break;
				}
				
				m_ioSocketState = (PQflush(m_connection) == 1 ?
					IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
			}
		}
		
		{
			PGnotify * notify;
			
			while((notify = PQnotifies(m_connection)))
			{
				if(m_notifyHandler)
					m_notifyHandler->notifyArrived(string(notify->relname));
					
				PQfreemem(notify);
			}
		}
	}
}

void PostgresSocket::pollWrite()
{
	if(!m_connected)
		return pollRead();
		
	m_ioSocketState = (PQflush(m_connection) == 1 ?
		IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
}

void PostgresSocket::pollError()
{
	string error = PQerrorMessage(m_connection);

	if(!error.empty())
		error.erase(error.size() - 1);
	
	LOG(L_CRIT, "%s: \"%s\"", (m_connected ? "Connecting to postgres server failed" :
		"Connection to postgres server died"), error.c_str());

	return m_parent->connectionDead(this);
}

void PostgresSocket::closeConnection()
{
	PQfinish(m_connection);
	m_connection = 0;
}

void PostgresSocket::sendQuery(string query, SqlRequestHandler * handler)
{
	if(m_connected && !PQisBusy(m_connection) && m_queue.empty())
	{
		RequestCache cache;
		cache.handler = handler;
		cache.type = RT_QUERY_SIMPLE;
		m_queue.push_back(cache);
		
		PQsendQuery(m_connection, query.c_str());
		
		m_ioSocketState = (PQflush(m_connection) == 1 ?
			IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
	}
	else
	{
		RequestCache cache;
		cache.query = query;
		cache.type = RT_QUERY_SIMPLE;
		cache.handler = handler;
		m_queue.push_back(cache);
	}
}

void PostgresSocket::prepareStatement(string name, string query,
	SqlRequestHandler * handler)
{
	if(m_connected && !PQisBusy(m_connection) && m_queue.empty())
	{
		RequestCache cache;
		cache.type = RT_PREPARE;
		cache.query = name;
		m_queue.push_back(cache);
		
		PQsendPrepare(m_connection, name.c_str(), query.c_str(), 0, 0);
		
		m_ioSocketState = (PQflush(m_connection) == 1 ?
			IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
	}
	else
	{
		RequestCache cache;
		cache.type = RT_PREPARE;
		cache.handler = handler;
		cache.query = query;
		cache.prepare.name = name;	
		m_queue.push_back(cache);
	}
}

void PostgresSocket::emitPreparedQuery(string name, list<SqlParameter>&
	parameters, bool binaryResult)
{
	const char * * paramValues = 0;
	int * paramLengths = 0;
	int * paramFormats = 0;
		
	if(!parameters.empty())
	{
		unsigned int k = 0;
		paramValues = new const char * [parameters.size()];
		// this is fucking nasty, i put these into one heapblock for performance
		// i could even put the above in the same, but some compilers use 32bit
		// for int on 64bit platforms, where a pointer naturally has 64bit
		paramLengths = new int [parameters.size() << 1];
		paramFormats = &paramLengths[parameters.size()];
		
		for(list<SqlParameter>::iterator it = parameters.begin();
			it != parameters.end(); ++it)
		{
			if(it->isNull)
			{
				paramValues[k] = 0;
				paramLengths[k] = 0;
				paramFormats[k] = 0;
			}
			else
			{
				paramValues[k] = it->value.data();				
				paramLengths[k] = it->value.size();
				paramFormats[k] = it->isBinary;
			}
			
			++k;
		}
	}
	
	PQsendQueryPrepared(m_connection, name.c_str(), parameters.size(),
		paramValues, paramLengths, paramFormats, binaryResult);	
	
	if(paramValues)
	{
		delete [] paramValues;
		delete [] paramLengths;
	}
}

void PostgresSocket::sendPreparedQuery(string name, list<SqlParameter>&
	parameters, bool binaryResult, SqlRequestHandler * handler)
{
#ifdef QUERY_LOG
	LOG("%s: %s, <...>, %c, %p", __PRETTY_FUNCTION__, name.c_str(), binaryResult ? '+' : '-', handler);

	for(list<SqlParameter>::iterator it = parameters.begin(); it != parameters.end(); ++it)
	{
		if(it->isBinary)
		{
			stringstream buf;
			buf << hex << noshowbase;

			for(string::iterator jt = it->value.begin(); jt != it->value.end(); ++jt)
				buf << (int) * jt;

			LOG(" -b-> %s", buf.str().c_str());
		}
		else
			LOG(" ---> '%s'", it->value.c_str());
	}
#endif

	if(m_connected && !PQisBusy(m_connection) && m_queue.empty())
	{
		RequestCache cache;
		cache.type = RT_QUERY_PREPARED;
		cache.handler = handler;
		cache.prepared.resultBinary = binaryResult;
		m_queue.push_back(cache);
		
		emitPreparedQuery(name, parameters, binaryResult);
		
		m_ioSocketState = (PQflush(m_connection) == 1 ?
			IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
	}
	else
	{
		RequestCache cache;
		cache.type = RT_QUERY_PREPARED;
		cache.handler = handler;
		cache.query = name;
		cache.prepared.parameters = parameters;
		cache.prepared.resultBinary = binaryResult;
		m_queue.push_back(cache);
	}
}

void PostgresSocket::sendPreparedQuery(string name, bool binaryResult,
	SqlRequestHandler * handler)
{
	if(m_connected && !PQisBusy(m_connection) && m_queue.empty())
	{
		RequestCache cache;
		cache.type = RT_QUERY_PREPARED;
		cache.handler = handler;
		cache.prepared.resultBinary = binaryResult;
		m_queue.push_back(cache);
		
		PQsendQueryPrepared(m_connection, name.c_str(), 0, 0, 0, 0,
			binaryResult);	
		
		m_ioSocketState = (PQflush(m_connection) == 1 ?
			IOSOCKSTAT_BUFFERING : IOSOCKSTAT_IDLE);
	}
	else
	{
		RequestCache cache;
		cache.type = RT_QUERY_PREPARED;
		cache.handler = handler;
		cache.query = name;
		cache.prepared.resultBinary = binaryResult;
		m_queue.push_back(cache);
	}
}

string PostgresSocket::escapeString(string input)
{
	char escaped[input.size() * 2 + 1];
	
	PQescapeStringConn(m_connection, escaped, input.data(), input.size(), 0);
	return string(escaped);
}

