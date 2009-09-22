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

#include "Daemon.hpp"


#ifndef __MWCOLLECTD_STREAMRECORDER_HPP
#define __MWCOLLECTD_STREAMRECORDER_HPP

#include <vector>
#include <string>
using namespace std;

#include <tr1/unordered_map>
using namespace std::tr1;

#include <pthread.h>
#include <errno.h>

#include <stdio.h>


namespace mwcollectd
{


class StreamRecorder
{
public:
	StreamRecorder(NetworkNode * source, NetworkNode * destination)
	{
		m_source = * source;
		m_destination = * destination;

		pthread_mutex_init(&m_dataMutex[0], 0);
		pthread_mutex_init(&m_dataMutex[1], 0);
		pthread_mutex_init(&m_propertiesMutex, 0);

		m_refCount = 1;
	}

	virtual ~StreamRecorder()
	{
		pthread_mutex_destroy(&m_dataMutex[0]);
		pthread_mutex_destroy(&m_dataMutex[1]);
		pthread_mutex_destroy(&m_propertiesMutex);
	}

	enum Direction
	{
		DIR_INCOMING = 0,
		DIR_OUTGOING = 1
	};


	//! IMPORTANT: There may be always only one thread writing to a StreamRecorder!
	void appendStreamData(Direction direction, const uint8_t * data, size_t length)
	{
		if(pthread_mutex_trylock(&m_dataMutex[direction]) == 0)
		{
			if(!m_buffer[direction].empty())
			{
				m_data[direction].append(m_buffer[direction]);
				m_buffer[direction].clear();
			}

			m_data[direction].append(data, length);
			pthread_mutex_unlock(&m_dataMutex[direction]);
		}
		else
			m_buffer[direction].append(data, length);
	}



	inline bool acquireStreamData(Direction direction)
	{
		return pthread_mutex_lock(&m_dataMutex[direction]) == 0;
	}

	inline void releaseStreamData(Direction direction)
	{
		pthread_mutex_unlock(&m_dataMutex[direction]);
	}

	inline const basic_string<uint8_t>& getStreamData(Direction direction)
	{
		return m_data[direction];
	}



	inline void setProperty(const char * property, string value)
	{
		pthread_mutex_lock(&m_propertiesMutex);
		m_properties[string(property)] = value;
		pthread_mutex_unlock(&m_propertiesMutex);
	}

	inline string getProperty(const char * property)
	{
		pthread_mutex_lock(&m_propertiesMutex);
		string result = m_properties[string(property)];
		pthread_mutex_unlock(&m_propertiesMutex);
		return result;
	}

	inline vector<pair<string, string> > getProperties()
	{
		vector<pair<string, string> > result;

		pthread_mutex_lock(&m_propertiesMutex);

		for(PropertyMap::iterator it = m_properties.begin();
			it != m_properties.end(); ++it)
		{
			result.push_back(* it);
		}

		pthread_mutex_unlock(&m_propertiesMutex);
		return result;
	}

	inline bool hasProperty(const char * property)
	{
		pthread_mutex_lock(&m_propertiesMutex);
		register bool result = m_properties.find(property) != m_properties.end();
		pthread_mutex_unlock(&m_propertiesMutex);
		return result;
	}

	inline const NetworkNode& getSource() const
	{ return m_source; }
	inline const NetworkNode& getDestination() const
	{ return m_destination; }



	// TODO FIXME: these might theoretically require locking, unless we use LOCK prefix on x86

	inline void acquire()
	{ ++m_refCount; }

	inline void release()
	{
		-- m_refCount;
		
		if(!m_refCount)
			delete this;		
	}

private:
	NetworkNode m_source, m_destination;

	basic_string<uint8_t> m_data[2];
	basic_string<uint8_t> m_buffer[2];

	typedef unordered_map<string, string> PropertyMap;
	PropertyMap m_properties;

	pthread_mutex_t m_dataMutex[2];
	pthread_mutex_t m_propertiesMutex;

	size_t m_refCount;
};


}


#endif // __MWCOLLECTD_STREAMRECORDER_HPP
