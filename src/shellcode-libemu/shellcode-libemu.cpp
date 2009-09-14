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

// TODO FIXME: autoconf check
#include <sys/sysinfo.h>

ShellcodeLibemuModule::ShellcodeLibemuModule(Daemon * daemon)
{
	m_daemon = daemon;
	m_exiting = false;

	pthread_mutex_init(&m_testQueueMutex, 0);
	pthread_cond_init(&m_testCond, 0);
	pthread_mutex_init(&m_resultQueueMutex, 0);
}

ShellcodeLibemuModule::~ShellcodeLibemuModule()
{
	pthread_cond_destroy(&m_testCond);
	pthread_mutex_destroy(&m_testQueueMutex);
	pthread_mutex_destroy(&m_resultQueueMutex);
}

bool ShellcodeLibemuModule::start(Configuration * config)
{
	size_t threads = 0;
	
	if(config)
		threads = config->getInteger(":threads", 0);

	if(!threads)
	{
		// TODO FIXME: add autoconf check for function
		threads = get_nprocs();
		LOG(L_INFO, "Creating %u shellcode testing threads.", threads);
	}

	m_threads.reserve(threads);

	for(size_t k = 0; k < threads; ++k)
	{
		AnalyzerThread * t = new AnalyzerThread(&m_testQueue, &m_testQueueMutex,
			&m_testCond, &m_resultQueue, &m_resultQueueMutex);

		if(!t->spawn())
			return false;

		m_threads.push_back(t);
	}

	if(!m_daemon->getEventManager()->subscribeEventMask("stream.finished", this)
		|| !m_daemon->getEventManager()->subscribeEventMask("shellcode.test", this))
	{
		return false;
	}

	m_daemon->registerLoopable(this);

	return true;
}

bool ShellcodeLibemuModule::stop()
{
	{
		pthread_mutex_lock(&m_testQueueMutex);

		if(!m_testQueue.empty())
		{
			pthread_mutex_unlock(&m_testQueueMutex);
			LOG(L_CRIT, __PRETTY_FUNCTION__);

			m_exiting = true;
			return false;
		}

		for(vector<AnalyzerThread *>::iterator it = m_threads.begin();
			it != m_threads.end(); ++it)
		{
			(* it)->deactivate();
		}

		pthread_mutex_unlock(&m_testQueueMutex);
	}
	
	pthread_cond_broadcast(&m_testCond);

	for(vector<AnalyzerThread *>::iterator it = m_threads.begin();
		it != m_threads.end(); ++it)
	{
		(* it)->join();
	}

	m_daemon->unregisterLoopable(this);

	m_daemon->getEventManager()->unsubscribeEventMask("stream.finished", this);
	m_daemon->getEventManager()->unsubscribeEventMask("shellcode.test", this);

	return true;
}

void ShellcodeLibemuModule::handleEvent(Event * ev)
{
	if(m_exiting)
		return;

	if(ev->getName() == "stream.finished")
	{
		StreamRecorder * recorder = (StreamRecorder *) (* ev)["recorder"].getPointerValue();

		recorder->acquire();

		pthread_mutex_lock(&m_testQueueMutex);
		m_testQueue.push_back(TestQueueItem(recorder));
		pthread_mutex_unlock(&m_testQueueMutex);
		pthread_cond_signal(&m_testCond);
	}
	else if(ev->getName() == "shellcode.test")
	{
		string source = * (* ev)["buffer"];
		basic_string<uint8_t> buffer;
		StreamRecorder * recorder = (StreamRecorder *) (* ev)["recorder"].getPointerValue();

		copy(source.begin(), source.end(), buffer.begin());
		recorder->acquire();

		pthread_mutex_lock(&m_testQueueMutex);
		m_testQueue.push_back(TestQueueItem(recorder, buffer));
		pthread_mutex_unlock(&m_testQueueMutex);
		pthread_cond_signal(&m_testCond);
	}
}

void ShellcodeLibemuModule::loop()
{
	Result result;

	updateEmulatorStates();

	for(list<EmulatorSession *>::iterator it = m_emulators.begin();
		it != m_emulators.end(); ++it)
	{
		if(!(* it)->step())
		{
			delete * it;
			it = m_emulators.erase(it);
		}
	}
		
	for(;;)
	{
		{
			pthread_mutex_lock(&m_resultQueueMutex);

			if(m_resultQueue.empty())
			{
				pthread_mutex_unlock(&m_resultQueueMutex);

				if(m_exiting)
					m_daemon->stop();

				return;
			}

			result = m_resultQueue.front();
			m_resultQueue.pop_front();
			pthread_mutex_unlock(&m_resultQueueMutex);
		}

		if(result.shellcodeOffset >= 0)
		{
			{
				char offsetString[10];

				if(result.test.type == TestQueueItem::QIT_RECORDER)
				{
					snprintf(offsetString, sizeof(offsetString) - 1, "%x",
						result.shellcodeOffset);
					result.test.recorder->setProperty("shellcode.offset", offsetString);
				}
				else
					strcpy(offsetString, "<buffer>");

				Event ev = Event("shellcode.detected");
				ev["recorder"] = (void *) result.test.recorder;
				m_daemon->getEventManager()->fireEvent(&ev);
			}

			{
				const basic_string<uint8_t> * stream;

				if(result.test.type == TestQueueItem::QIT_RECORDER)
				{
					result.test.recorder->acquireStreamData(StreamRecorder::DIR_INCOMING);
					stream = &result.test.recorder->getStreamData(StreamRecorder::DIR_INCOMING);
				}
				else
					stream = &result.test.buffer;

				EmulatorSession * emu = new EmulatorSession(stream->data(),
					stream->size(), result.shellcodeOffset, m_daemon,
					result.test.recorder);
				m_emulators.push_back(emu);

				if(result.test.type == TestQueueItem::QIT_RECORDER)
					result.test.recorder->releaseStreamData(StreamRecorder::DIR_INCOMING);
			}
		}
		else
			LOG(L_SPAM, "No shellcode for recorder %p.", result.test.recorder);
		
		result.test.recorder->release();
	}
}

void ShellcodeLibemuModule::updateEmulatorStates()
{
	for(list<EmulatorSession *>::iterator next, it = m_emulators.begin(); it != m_emulators.end(); it = next)
	{
		next = it; ++next;

		if(! (* it)->isActive())
		{
			m_sleepingEmulators.push_back(* it);
			m_emulators.erase(it);
		}
	}

	for(list<EmulatorSession *>::iterator next, it = m_sleepingEmulators.begin(); it != m_sleepingEmulators.end(); it = next)
	{
		next = it; ++next;

		if((* it)->isActive())
		{
			m_emulators.push_back(* it);
			m_sleepingEmulators.erase(it);
		}
	}
}


EXPORT_LIBNETWORKD_MODULE(ShellcodeLibemuModule, Daemon *);
