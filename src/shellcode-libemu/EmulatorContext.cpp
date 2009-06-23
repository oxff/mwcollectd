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
	uint32_t startOffset, Daemon * daemon)
{
	m_emu = emu_new();
	m_env = emu_env_new(m_emu);

	m_steps = 0;

	if(!m_emu || !m_env)
		throw;

	m_daemon = daemon;

	struct emu_memory * mem = emu_memory_get(m_emu);
	m_cpu = emu_cpu_get(m_emu);

	// Do not use a static value or you'll run into easy detectability,
	// but not initializing this either could be yield memory disclosure vuln.
	for(int i = 0; i < 8; ++i)
		emu_cpu_reg32_set(m_cpu, (emu_reg32) i, rand());

	// Somebody please show Markus const pointers... :/
	emu_memory_write_block(mem, CODE_OFFSET, (void *) data, size);
	emu_cpu_eip_set(m_cpu, CODE_OFFSET + startOffset);

	registerHooks();
}

EmulatorSession::~EmulatorSession()
{
	if(m_emu)
		emu_free(m_emu);

	if(m_env)
		emu_env_free(m_env);
}

void EmulatorSession::registerHooks()
{
	emu_env_w32_export_hook(m_env, "ExitProcess", schooks::hook_ExitProcess, this);
	emu_env_w32_export_hook(m_env, "ExitThread", schooks::hook_ExitThread, this);

	emu_env_w32_load_dll(m_env->env.win, (char *) "urlmon.dll");
	emu_env_w32_export_hook(m_env, "URLDownloadToFileA", schooks::hook_URLDownloadToFile, this);


	// TODO: moar...
}

bool EmulatorSession::step()
{
#ifdef BENCHMARK_LIBEMU
	struct timeval start, end;

	gettimeofday(&start, 0);
#endif

	for(size_t k = 0; k < 4096; ++k)
	{
		if(++m_steps > 1000000)
		{
			LOG(L_CRIT, "Exceeded max steps limit.");

			return false;
		}

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
			LOG(L_INFO, "Failed to step CPU for shellcode [%u]: %s", m_steps, emu_strerror(m_emu));
			return false;
		}
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
	LOG(L_INFO, "Shellcode downloads remote URL \"%s\" to \"%s\".",
		url, filename);
}


