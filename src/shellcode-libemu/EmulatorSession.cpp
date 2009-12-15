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

#undef BENCHMARK_LIBEMU

#ifdef BENCHMARK_LIBEMU
#include <sys/time.h>
#endif


// taken from libemu's sctest, seems sane (win32 heap)
#define CODE_OFFSET 0x417000


EmulatorSession::EmulatorSession(const uint8_t * data, size_t size,
	uint32_t startOffset, Daemon * daemon, StreamRecorder * recorder,
	uint32_t timeoutLimit)
{
	m_emu = emu_new();
	m_env = emu_env_new(m_emu);

	m_steps = 0;
	m_active = true;
	m_sockfdCounter = 1952;

	if(!m_emu || !m_env)
		throw;

	m_daemon = daemon;

	struct emu_memory * mem = emu_memory_get(m_emu);
	m_cpu = emu_cpu_get(m_emu);

	// Do not use a static value or you'll run into easy detectability,
	// but not initializing this either could result in a memory disclosure vuln.
	for(int i = 0; i < 8; ++i)
		emu_cpu_reg32_set(m_cpu, (emu_reg32) i, rand());

	// Somebody please show Markus const pointers... :/
	emu_memory_write_block(mem, CODE_OFFSET, (void *) data, size);
	emu_cpu_eip_set(m_cpu, CODE_OFFSET + startOffset);

	emu_cpu_reg32_set(m_cpu, esp, 0x0012fe98);

	registerHooks();

	m_recorder = recorder;
	m_recorder->acquire();

	m_Timeout = daemon->getTimeoutManager()->scheduleTimeout(timeoutLimit, this);
}

EmulatorSession::~EmulatorSession()
{
	if(m_emu)
		emu_free(m_emu);

	if(m_env)
		emu_env_free(m_env);

	if(m_recorder)
		m_recorder->release();
	
	for(unordered_map<int32_t, EmulatorSocket *>::iterator it = m_sockets.begin();
		it != m_sockets.end(); ++it)
	{
		m_daemon->getNetworkManager()->removeSocket(it->second);
		delete it->second;
	}

	if(m_Timeout != TIMEOUT_EMPTY)
		m_daemon->getTimeoutManager()->dropTimeout(m_Timeout);
}

void EmulatorSession::registerHooks()
{
	emu_env_w32_export_hook(m_env, "CreateFileA", schooks::hook_CreateFile, this);
	emu_env_w32_export_hook(m_env, "WriteFile", schooks::hook_WriteFile, this);
	emu_env_w32_export_hook(m_env, "CloseHandle", schooks::hook_CloseHandle, this);

	emu_env_w32_export_hook(m_env, "CreateProcessA", schooks::hook_CreateProcess, this);
	emu_env_w32_export_hook(m_env, "WinExec", schooks::hook_WinExec, this);
	emu_env_w32_export_hook(m_env, "ExitProcess", schooks::hook_ExitProcess, this);
	emu_env_w32_export_hook(m_env, "ExitThread", schooks::hook_ExitThread, this);

	emu_env_w32_load_dll(m_env->env.win, (char *) "urlmon.dll");
	emu_env_w32_export_hook(m_env, "URLDownloadToFileA", schooks::hook_URLDownloadToFile, this);

	emu_env_w32_load_dll(m_env->env.win, (char *) "ws2_32.dll");
	emu_env_w32_export_hook(m_env, "socket", schooks::hook_socket, this);
	emu_env_w32_export_hook(m_env, "closesocket", schooks::hook_closesocket, this);
	emu_env_w32_export_hook(m_env, "connect", schooks::hook_connect, this);
	emu_env_w32_export_hook(m_env, "bind", schooks::hook_bind, this);
	emu_env_w32_export_hook(m_env, "listen", schooks::hook_listen, this);
	emu_env_w32_export_hook(m_env, "accept", schooks::hook_accept, this);
	emu_env_w32_export_hook(m_env, "recv", schooks::hook_recv, this);
	emu_env_w32_export_hook(m_env, "send", schooks::hook_send, this);
}

bool EmulatorSession::step()
{
#ifdef BENCHMARK_LIBEMU
	struct timeval start, end;

	gettimeofday(&start, 0);
#endif
	size_t k;

	if(m_Timeout == TIMEOUT_EMPTY)
		return false;

	for(k = 0; m_active && k < 4096; ++k)
	{

		struct emu_env_hook * userHook;

		userHook = emu_env_w32_eip_check(m_env);

		if(userHook)
		{
			if(!userHook->hook.win->fnhook)
			{
				LOG(L_CRIT, "Unhooked call to \"%s\" in shellcode.", userHook->hook.win->fnname);
				return false;
			}

			return true;
		}

		if(emu_cpu_parse(m_cpu) < 0)
		{
			LOG(L_INFO, "Unrecognized instruction in shellcode: %s", emu_strerror(m_emu));
			return false;
		}

		// TODO: add support for linux system calls here...
		
		if(emu_cpu_step(m_cpu) < 0)
		{
			string error = emu_strerror(m_emu);
			error.erase(error.size() - 1);

			LOG(L_INFO, "Failed to step CPU for shellcode [%u]: \"%s\"", m_steps, error.c_str());
			return false;
		}
	}
		
	if((m_steps += k) > 1000000)
	{
		LOG(L_CRIT, "Exceeded max steps limit.");
		return false;
	}


#ifdef BENCHMARK_LIBEMU
	gettimeofday(&end, 0);

	end.tv_usec += (end.tv_sec - start.tv_sec) * 1000000;
	LOG(L_INFO, "%s run: %u us", __PRETTY_FUNCTION__, end.tv_usec - start.tv_usec);
#endif

	return true;
}


void EmulatorSession::addDirectDownload(const char * url, const char * filename)
{
	LOG(L_INFO, "Shellcode in %p downloads remote URL \"%s\" to \"%s\".",
		m_recorder, url, filename);

	m_recorder->setProperty("url", url);
	m_recorder->setProperty((string("localfile:") + url).c_str(), filename);

	{
		Event ev = Event("shellcode.download");

		ev["url"] = url;
		ev["recorder"] = (void *) m_recorder;

		m_daemon->getEventManager()->fireEvent(&ev);
	}
}


void EmulatorSession::socketWakeup(int result)
{
	m_active = true;
	emu_cpu_reg32_set(m_cpu, eax, (uint32_t) result);
}


int EmulatorSession::createSocket()
{
	if(m_sockets.size() >= 4)
		return -1;

	EmulatorSocket * socket = new EmulatorSocket(this, emu_memory_get(m_emu));

	if(!socket->socket())
	{
		delete socket;
		return -1;
	}

	m_daemon->getNetworkManager()->addSocket(socket, socket->getFd());

	m_sockfdCounter -= 4;
	m_sockets[m_sockfdCounter] = socket;

	LOG(L_SPAM, "%p creates new socket %p as %u.", m_recorder, socket, m_sockfdCounter);

	return m_sockfdCounter;
}

int EmulatorSession::registerSocket(EmulatorSocket * socket)
{
	if(m_sockets.size() >= 4)
	{
		delete socket;
		return -1;
	}

	m_daemon->getNetworkManager()->addSocket(socket, socket->getFd());

	m_sockfdCounter -= 4;
	m_sockets[m_sockfdCounter] = socket;

	LOG(L_INFO, "Registered new socket %p as %u.", socket, m_sockfdCounter);

	return m_sockfdCounter;
}

int EmulatorSession::destroySocket(int fd)
{
	unordered_map<int32_t, EmulatorSocket *>::iterator it = m_sockets.find(fd);

	if(it == m_sockets.end())
		return  -1;

	m_daemon->getNetworkManager()->removeSocket(it->second);
	delete it->second;

	m_sockets.erase(it);

	return 0;
}


uint32_t EmulatorSession::createFile(const char * filename)
{
	uint32_t handle;

	do {
		handle = ((rand() & 0xff) << 16) | (rand() & 0xfff0);
	} while (m_files.find(handle) != m_files.end());

	m_files[handle] = VirtualFile();
	m_files[handle].name = filename;
	return handle;
}

bool EmulatorSession::appendFile(uint32_t handle, uint8_t * buffer, uint32_t length)
{
	unordered_map<uint32_t, VirtualFile>::iterator it = m_files.find(handle);

	if(it == m_files.end())
		return false;

	it->second.contents.append((char *) buffer, length);
	it->second.off += length;

	return true;
}

void EmulatorSession::closeHandle(uint32_t handle)
{
	unordered_map<uint32_t, VirtualFile>::iterator it = m_files.find(handle);

	if(it == m_files.end())
		return;

	LOG(L_SPAM, "Shellcode in %p wrote \"%s\", %u bytes.", m_recorder,
		it->second.name.c_str(), it->second.contents.size());

	m_recorder->setProperty(("file:" + it->second.name).c_str(), it->second.contents);

	{
		Event ev = Event("shellcode.file");

		ev["recorder"] = (void *) m_recorder;
		ev["name"] = it->second.name;
		ev["url"] = "shellcode://";

		m_daemon->getEventManager()->fireEvent(&ev);
	}

	m_files.erase(it);
}


void EmulatorSession::createProcess(const char * image, const char * commandline)
{
	Event ev = Event("shellcode.process");

	ev["recorder"] = (void *) m_recorder;

	if(image)
		ev["image"] = image;

	if(commandline)
		ev["commandline"] = commandline;

	m_daemon->getEventManager()->fireEvent(&ev);
}


void EmulatorSession::timeoutFired(Timeout t)
{
	if(m_Timeout == t)
	{
		m_active = true;
		m_Timeout = TIMEOUT_EMPTY;
	}
}

