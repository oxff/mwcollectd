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
#include <tr1/unordered_map>
using namespace std;
using namespace std::tr1;

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



class EmulatorSession;

class EmulatorSocket : public IOSocket
{
public:
	inline EmulatorSocket(EmulatorSession * session, struct emu_memory * memory)
		: m_fd(-1), m_rbuf(0), m_state(SS_UNINIT)
	{ m_session = session; m_memory = memory; m_ioSocketState = IOSOCKSTAT_IGNORE; }

	virtual ~EmulatorSocket();

	virtual void pollRead();
	virtual void pollWrite();
	virtual void pollError();

	bool socket();
	int write(const uint8_t * buffer, size_t length);
	int read(uint32_t guestbuf, size_t length);
	int connect(uint32_t addr, uint16_t port);
	int bind(uint32_t addr, uint16_t port);
	int listen(uint32_t backlog);
	int accept(uint32_t guestaddr, uint32_t addrsize);

	inline int getFd()
	{ return m_fd; }

protected:
	inline EmulatorSocket(int fd, EmulatorSession * session, struct emu_memory * memory)
		: m_rbuf(0), m_state(SS_CONNECTED)
	{ m_fd = fd; m_session = session; m_memory = memory; m_ioSocketState = IOSOCKSTAT_IGNORE; }

private:
	int m_fd;

	basic_string<uint8_t> m_outputBuffer;
	EmulatorSession * m_session;

	uint32_t m_rbuf;
	size_t m_rsize, m_wsize;

	enum SocketState
	{
		SS_UNINIT,
		SS_CONNECTING,
		SS_LISTENING,
		SS_CONNECTED,
	} m_state;

	struct emu_memory * m_memory;
};

class EmulatorSession
{
public:
	EmulatorSession(const uint8_t * data, size_t size, uint32_t startOffset,
		Daemon * daemon, StreamRecorder * recorder);
	~EmulatorSession();

	bool step();

	inline bool isActive()
	{ return m_active; }
	inline void yield()
	{ m_active = false; }

	void addDirectDownload(const char * url, const char * localFile);


	int createSocket();
	int destroySocket(int fd);

	inline EmulatorSocket * getSocket(int fd)
	{
		unordered_map<int32_t, EmulatorSocket *>::iterator it = m_sockets.find(fd);

		if(it == m_sockets.end())
			return 0;

		return it->second;
	}


	uint32_t createFile(const char * filename);
	bool appendFile(uint32_t handle, uint8_t * buffer, uint32_t length);
	void closeHandle(uint32_t handle);


	void createProcess(const char * image, const char * cmd);	

	inline void resetStepCounter()
	{ m_steps = 0; }

protected:
	void registerHooks();

	int registerSocket(EmulatorSocket * socket);
	void socketWakeup(int result);
	friend class EmulatorSocket;

private:
	struct emu * m_emu;
	struct emu_env * m_env;
	struct emu_cpu * m_cpu;

	uint32_t m_steps;

	class VirtualFile
	{
	public:
		VirtualFile()
		{ off = 0; }

		string name;
		basic_string<uint8_t> contents;
		uint32_t off;
	};

	unordered_map<int32_t, EmulatorSocket *> m_sockets;
	unordered_map<uint32_t, VirtualFile> m_files;

	uint32_t m_sockfdCounter;

	Daemon * m_daemon;
	StreamRecorder * m_recorder;
	bool m_active;
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
		
protected:
	struct TestQueueItem
	{
		enum QueueItemType
		{
			QIT_UNITIALIZED = 0,
			QIT_RECORDER,
			QIT_BUFFER,
		};

		QueueItemType type;

		StreamRecorder * recorder;
		string buffer;

		inline TestQueueItem(StreamRecorder * r)
			: recorder(r)
		{ type = QIT_RECORDER; }

		inline TestQueueItem(StreamRecorder * r, const string& buf)
			: recorder(r), buffer(buf)
		{ type = QIT_BUFFER; }

		inline TestQueueItem()
			: type(QIT_UNITIALIZED)
		{ }
	};
	
	struct Result
	{
		TestQueueItem test;
		int shellcodeOffset;
	};

	friend class AnalyzerThread;

	void updateEmulatorStates();

private:
	Daemon * m_daemon;

	list<TestQueueItem> m_testQueue;
	pthread_mutex_t m_testQueueMutex;
	pthread_cond_t m_testCond;

	list<Result> m_resultQueue;
	pthread_mutex_t m_resultQueueMutex;

	vector<AnalyzerThread *> m_threads;

	list<EmulatorSession *> m_emulators, m_sleepingEmulators;

	bool m_exiting;
};


class AnalyzerThread
{
public:
	AnalyzerThread(list<ShellcodeLibemuModule::TestQueueItem> * queue, pthread_mutex_t * mutex,
		pthread_cond_t * condition, list<ShellcodeLibemuModule::Result> *
		resultQueue, pthread_mutex_t * m_resultMutex);

	bool spawn();
	void deactivate();
	void join();

protected:
	static inline void * threadTrampoline(void * instance)
	{ ((AnalyzerThread *) instance)->run(); return 0; }
	void run();

	int check(ShellcodeLibemuModule::TestQueueItem& test);

private:
	list<ShellcodeLibemuModule::TestQueueItem> * m_testQueue;
	pthread_mutex_t * m_testQueueMutex;
	pthread_cond_t * m_testAvailable;
	pthread_t m_meself;

	list<ShellcodeLibemuModule::Result> * m_resultQueue;
	pthread_mutex_t * m_resultQueueMutex;

	bool m_active;
};


#endif // __MWCOLLECTD_SHELLCODELIBEMU_HPP
