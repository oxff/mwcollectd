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


#include <mwcollectd.hpp>

#include <errno.h>


namespace mwcollectd
{


StreamRecorder::StreamRecorder(NetworkNode& source, NetworkNode& destination)
{
	m_source = source;
	m_destination = destination;

	pthread_mutex_init(&m_dataMutex[0], 0);
	pthread_mutex_init(&m_dataMutex[1], 0);
	pthread_mutex_init(&m_propertiesMutex, 0);

	m_refCount = 1;
}

StreamRecorder::~StreamRecorder()
{
	pthread_mutex_destroy(&m_dataMutex[0]);
	pthread_mutex_destroy(&m_dataMutex[1]);
	pthread_mutex_destroy(&m_propertiesMutex);
}

void StreamRecorder::release()
{
	-- m_refCount;

	if(!m_refCount)
		delete this;
}

void StreamRecorder::setProperty(string& property, string& value)
{
	pthread_mutex_lock(&m_propertiesMutex);
	m_properties[property] = value;
	pthread_mutex_unlock(&m_propertiesMutex);
}

string StreamRecorder::getProperty(string& property)
{
	pthread_mutex_lock(&m_propertiesMutex);
	string result = m_properties[property];
	pthread_mutex_unlock(&m_propertiesMutex);
	return result;
}

vector<pair<string, string> > StreamRecorder::getProperties()
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

bool StreamRecorder::hasProperty(string& property)
{
	pthread_mutex_lock(&m_propertiesMutex);
	register bool result = m_properties.find(property) != m_properties.end();
	pthread_mutex_unlock(&m_propertiesMutex);
	return result;
}

void StreamRecorder::appendStreamData(Direction direction, const uint8_t * data,
	size_t length)
{
	if(pthread_mutex_trylock(&m_dataMutex[direction]) != EBUSY)
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

basic_string<uint8_t> StreamRecorder::copyStreamData(Direction direction)
{
	pthread_mutex_lock(&m_dataMutex[direction]);

	if(!m_buffer[direction].empty())
	{
		m_data[direction].append(m_buffer[direction]);
		m_buffer[direction].clear();
	}

	basic_string<uint8_t> result = m_data[direction];
	pthread_mutex_unlock(&m_dataMutex[direction]);
	return result;
}


}

