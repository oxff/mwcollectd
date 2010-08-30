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
	
#define MAP_ACTION(name, ev) \
	void CurlSocket::name() \
	{ \
		int runningHandles; \
		while(curl_multi_socket_action(g_module->getCurlMulti(), m_fd, ev, &runningHandles) == CURLM_CALL_MULTI_PERFORM); \
		\
		g_module->checkFinished(runningHandles); \
	}

MAP_ACTION(pollRead, CURL_CSELECT_IN);
MAP_ACTION(pollWrite, CURL_CSELECT_OUT);
MAP_ACTION(pollError, CURL_CSELECT_ERR);
