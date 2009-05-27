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

extern "C" {
#include <emu/emu.h>
#include <emu/emu_log.h>
#include <emu/emu_shellcode.h>
#include <emu/emu_memory.h>
#include <emu/emu_cpu.h>
#include <emu/emu_cpu_data.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
}


ShellcodeLibemuModule::ShellcodeLibemuModule(Daemon * daemon)
{
	m_daemon = daemon;
}

bool ShellcodeLibemuModule::start(Configuration * config)
{
	if(!m_daemon->getEventManager()->subscribeEventMask("stream.finished", this))
		return false;

	return true;
}

bool ShellcodeLibemuModule::stop()
{
	return true;
}

void ShellcodeLibemuModule::handleEvent(Event * ev)
{
	if(ev->getName() == "stream.finished")
	{
		StreamRecorder * recorder = (StreamRecorder *)
			(* ev)["recorder"].getPointerValue();

		recorder->acquire();
		checkRecorder(recorder);
		recorder->release();
	}
}

void ShellcodeLibemuModule::checkRecorder(StreamRecorder * recorder)
{
	struct emu * e;
	int offset;
	basic_string<uint8_t> data = recorder->copyStreamData(recorder->DIR_INCOMING);

	if(!(e = emu_new()))
	{
		LOG(L_CRIT, "Failed to create new libemu instance in %s!", __PRETTY_FUNCTION__);
		return;
	}

	if((offset = emu_shellcode_test(e, (uint8_t *) data.data(), data.size())) >= 0)
	{
		LOG(L_INFO, "Found shellcode in recorder %p at offset %i!", recorder, offset);
	}
	else
		LOG(L_SPAM, "No shellcode in recorder %p.", recorder);

	emu_free(e);
}


EXPORT_LIBNETWORKD_MODULE(ShellcodeLibemuModule, Daemon *);
