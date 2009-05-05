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

#ifndef __MWCOLLECTD_STREAMRECORDER_HPP
#define __MWCOLLECTD_STREAMRECORDER_HPP

#include <vector>
#include <string>
using namespace std;

#include <tr1/unordered_map>
using namespace std::tr1;

#include <pthread.h>


namespace mwcollectd
{


class StreamRecorder
{
public:
	StreamRecorder(NetworkNode& source, NetworkNode& destination);
	~StreamRecorder();

	enum Direction
	{
		DIR_INCOMING = 0,
		DIR_OUTGOING = 1
	};

	void appendStreamData(Direction direction, const uint8_t * data, size_t length);
	basic_string<uint8_t> copyStreamData(Direction direction);

	void setProperty(string& property, string& value);
	string getProperty(string& propert);
	vector<pair<string, string> > getProperties();
	bool hasProperty(string& property);

	inline NetworkNode getSource()
	{ return m_source; }
	inline NetworkNode getDestination()
	{ return m_destination; }

	inline void acquire()
	{ ++m_refCount; }
	void release();

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
