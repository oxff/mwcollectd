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


#ifndef __MWCOLLECTD_SHELLCODELIBEMU_HPP
#define __MWCOLLECTD_SHELLCODELIBEMU_HPP


#include <libnetworkd/libnetworkd.hpp>
using namespace libnetworkd;

#include <mwcollectd.hpp>
using namespace mwcollectd;


#include <list>
using namespace std;

#include <pthread.h>


class AnalyzerThread;

class ShellcodeLibemuModule : public Module, public EventSubscriber, public CoreLoopable
{
public:
	ShellcodeLibemuModule(Daemon * daemon);
	virtual ~ShellcodeLibemuModule();

	virtual bool start(Configuration * moduleConfiguration);
	virtual bool stop();

	virtual const char * getName() { return "shellcode-libemu"; }
	virtual const char * getDescription() { return "Detect and interpret"
		" shellcodes based on Baecher's & Koetter's libemu."; }

	virtual void handleEvent(Event * event);

	virtual void loop();


	struct Result
	{
		StreamRecorder * recorder;
		int shellcodeOffset;
	};

private:
	Daemon * m_daemon;

	list<StreamRecorder *> m_testQueue;
	pthread_mutex_t m_testQueueMutex;
	pthread_cond_t m_testCond;

	list<Result> m_resultQueue;
	pthread_mutex_t m_resultQueueMutex;

	vector<AnalyzerThread *> m_threads;

	bool m_exiting;
};


class AnalyzerThread
{
public:
	AnalyzerThread(list<StreamRecorder *> * queue, pthread_mutex_t * mutex,
		pthread_cond_t * condition, list<ShellcodeLibemuModule::Result> *
		resultQueue, pthread_mutex_t * m_resultMutex);

	bool spawn();
	void deactivate();
	void join();

protected:
	static inline void * threadTrampoline(void * instance)
	{ ((AnalyzerThread *) instance)->run(); return 0; }
	void run();

	int checkRecorder(StreamRecorder * recorder);

private:
	list<StreamRecorder *> * m_testQueue;
	pthread_mutex_t * m_testQueueMutex;
	pthread_cond_t * m_testAvailable;
	pthread_t m_meself;

	list<ShellcodeLibemuModule::Result> * m_resultQueue;
	pthread_mutex_t * m_resultQueueMutex;

	bool m_active;
};




#endif // __MWCOLLECTD_SHELLCODELIBEMU_HPP
