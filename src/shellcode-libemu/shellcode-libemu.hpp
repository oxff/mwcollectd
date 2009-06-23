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


extern "C" {
#include "emu/emu.h"
#include "emu/emu_memory.h"
#include "emu/emu_cpu.h"
#include "emu/emu_log.h"
#include "emu/emu_cpu_data.h"
#include "emu/emu_cpu_stack.h"
#include "emu/environment/emu_profile.h"
#include "emu/environment/emu_env.h"
#include "emu/environment/win32/emu_env_w32.h"
#include "emu/environment/win32/emu_env_w32_dll.h"
#include "emu/environment/win32/emu_env_w32_dll_export.h"
#include "emu/environment/win32/env_w32_dll_export_kernel32_hooks.h"
#include "emu/environment/linux/emu_env_linux.h"
#include "emu/emu_getpc.h"
#include "emu/emu_graph.h"
#include "emu/emu_string.h"
#include "emu/emu_hashtable.h"

#include "emu/emu_shellcode.h"
}

#include "schooks.hpp"



class EmulatorSession
{
public:
	EmulatorSession(const uint8_t * data, size_t size, uint32_t startOffset,
		Daemon * daemon);
	~EmulatorSession();

	bool step();

	void addDirectDownload(const char * url, const char * localFile);

protected:
	void registerHooks();

private:
	struct emu * m_emu;
	struct emu_env * m_env;
	struct emu_cpu * m_cpu;

	uint32_t m_steps;

	Daemon * m_daemon;
};

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
	virtual bool computationPending()
	{ return !m_emulators.empty(); }


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

	list<EmulatorSession *> m_emulators;

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
