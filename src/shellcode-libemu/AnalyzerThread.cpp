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

#include "shellcode-libemu.hpp"

#include <signal.h>



AnalyzerThread::AnalyzerThread(list<ShellcodeLibemuModule::TestQueueItem> * queue, pthread_mutex_t * mutex,
	pthread_cond_t * condition, list<ShellcodeLibemuModule::Result> * resultQueue,
	pthread_mutex_t * resultMutex)
{
	m_testQueue = queue;
	m_testQueueMutex = mutex;
	m_testAvailable = condition;

	m_resultQueue = resultQueue;
	m_resultQueueMutex = resultMutex;

	m_active = true;
}

bool AnalyzerThread::spawn()
{
	return pthread_create(&m_meself, 0, threadTrampoline, this) == 0;
}

void AnalyzerThread::run()
{
	ShellcodeLibemuModule::TestQueueItem test;
	ShellcodeLibemuModule::Result result;

	sigset_t signalSet;
	sigfillset(&signalSet);

	if(pthread_sigmask(SIG_SETMASK, &signalSet, 0) != 0)
		return;

	for(;;)
	{
		{
			pthread_mutex_lock(m_testQueueMutex);

			while(m_testQueue->empty() && m_active)
				pthread_cond_wait(m_testAvailable, m_testQueueMutex);

			if(!m_active)
			{
				pthread_mutex_unlock(m_testQueueMutex);
				return;
			}

			test = m_testQueue->front();
			m_testQueue->pop_front();
			pthread_mutex_unlock(m_testQueueMutex);
		}

		result.test = test;
		result.shellcodeOffset = check(test);

		pthread_mutex_lock(m_resultQueueMutex);
		m_resultQueue->push_back(result);
		pthread_mutex_unlock(m_resultQueueMutex);
	}
}


//! IMPORTANT: caller has to lock m_testQueue
void AnalyzerThread::deactivate()
{
	m_active = false;
}

void AnalyzerThread::join()
{
	void * result;

	pthread_join(m_meself, &result);
}

int AnalyzerThread::check(ShellcodeLibemuModule::TestQueueItem& test)
{
	struct emu * e;
	int offset;
	const basic_string<uint8_t> * data;

	if(test.type == ShellcodeLibemuModule::TestQueueItem::QIT_RECORDER)
	{
		test.recorder->acquireStreamData(test.recorder->DIR_INCOMING);
		data = &test.recorder->getStreamData(test.recorder->DIR_INCOMING);
	}
	else
		data = &test.buffer;

	if(!(e = emu_new()))
	{
		printf("Failed to create new libemu instance in %s!\n", __PRETTY_FUNCTION__);
		exit(0);
	}

	offset = emu_shellcode_test(e, (uint8_t *) data->data(), data->size());

	emu_free(e);

	if(test.type == ShellcodeLibemuModule::TestQueueItem::QIT_RECORDER)
		test.recorder->releaseStreamData(test.recorder->DIR_INCOMING);

	return offset;
}

