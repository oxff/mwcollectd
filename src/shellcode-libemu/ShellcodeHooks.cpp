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
#include <stdarg.h>


namespace schooks
{



uint32_t hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	return 0;
}

uint32_t hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	return 0;
}

uint32_t hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);


	/*void * pCaller    = */(void)va_arg(vl, void *);
	char * szURL      = va_arg(vl, char *);
	char * szFileName = va_arg(vl, char *);
	/*int    dwReserved = */(void)va_arg(vl, int   );
	/*void * lpfnCB     = */(void)va_arg(vl, void *);

	((EmulatorSession *) hook->hook.win->userdata)->addDirectDownload(szURL, szFileName);

	va_end(vl);
	return 0;
}



uint32_t hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);


#if 0
	int family = va_arg(vl, int);
	int type = va_arg(vl, int);
	int extra = va_arg(vl, int);
#endif

	int socket = ((EmulatorSession *) hook->hook.win->userdata)->createSocket();

	va_end(vl);
	return (uint32_t) socket;
}

uint32_t hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	int fd = va_arg(vl, int);

	EmulatorSocket * socket = ((EmulatorSession *) hook->hook.win->userdata)->getSocket(fd);

	if(!socket)
		return (uint32_t) -1;

	va_end(vl);
	return ((EmulatorSession *) hook->hook.win->userdata)->destroySocket(fd);
}

uint32_t hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	int fd = va_arg(vl, int);
	struct sockaddr_in * addr = va_arg(vl, struct sockaddr_in *);
	uint32_t namelen = va_arg(vl, uint32_t);

	((EmulatorSession *) hook->hook.win->userdata)->resetStepCounter();

	EmulatorSocket * socket = ((EmulatorSession *) hook->hook.win->userdata)->getSocket(fd);

	if(!socket || namelen < 8)
		return (uint32_t) -1;

	int res = socket->connect(addr->sin_addr.s_addr, addr->sin_port);
	// int res = socket->connect(0x0100007f, htons(4711));
	
	if(res == -2)
	{
		((EmulatorSession *) hook->hook.win->userdata)->yield();

		va_end(vl);
		return 0;
	}

	va_end(vl);
	return res;
}

uint32_t hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	int fd = va_arg(vl, int);
	struct sockaddr_in * addr = va_arg(vl, struct sockaddr_in *);
	uint32_t namelen = va_arg(vl, uint32_t);

	((EmulatorSession *) hook->hook.win->userdata)->resetStepCounter();

	EmulatorSocket * socket = ((EmulatorSession *) hook->hook.win->userdata)->getSocket(fd);

	if(!socket || namelen < 8)
		return (uint32_t) -1;

	int res = socket->bind(addr->sin_addr.s_addr, addr->sin_port);
	va_end(vl);
	return res;
}

uint32_t hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	int fd = va_arg(vl, int);
	uint32_t backlog = va_arg(vl, uint32_t);

	((EmulatorSession *) hook->hook.win->userdata)->resetStepCounter();

	EmulatorSocket * socket = ((EmulatorSession *) hook->hook.win->userdata)->getSocket(fd);

	if(!socket)
		return (uint32_t) -1;

	int res = socket->listen(backlog);
	va_end(vl);
	return res;
}

uint32_t hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	int fd = va_arg(vl, int);
	uint32_t guestaddr = va_arg(vl, uint32_t);
	uint32_t namelen = va_arg(vl, uint32_t);

	((EmulatorSession *) hook->hook.win->userdata)->resetStepCounter();

	EmulatorSocket * socket = ((EmulatorSession *) hook->hook.win->userdata)->getSocket(fd);

	if(!socket)
		return (uint32_t) -1;

	int res = socket->accept(guestaddr, namelen);
	
	if(res == -2)
	{
		((EmulatorSession *) hook->hook.win->userdata)->yield();

		va_end(vl);
		return 0;
	}

	va_end(vl);
	return res;
}

uint32_t hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	int fd = va_arg(vl, int);
	uint32_t buf = va_arg(vl, uint32_t);
	uint32_t len =  va_arg(vl, uint32_t);
	(void) va_arg(vl, int); // flags

	((EmulatorSession *) hook->hook.win->userdata)->resetStepCounter();

	EmulatorSocket * socket = ((EmulatorSession *) hook->hook.win->userdata)->getSocket(fd);

	if(!socket)
		return (uint32_t) -1;

	int res = socket->read(buf, len);

	if(res == -2)
	{
		((EmulatorSession *) hook->hook.win->userdata)->yield();

		va_end(vl);
		return 0;
	}

	va_end(vl);
	return (uint32_t) res;
}


uint32_t hook_send(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	int fd = va_arg(vl, int);
	uint8_t * buf = va_arg(vl, uint8_t *);
	uint32_t len = va_arg(vl, uint32_t);

	((EmulatorSession *) hook->hook.win->userdata)->resetStepCounter();

	EmulatorSocket * socket = ((EmulatorSession *) hook->hook.win->userdata)->getSocket(fd);

	if(!socket)
		return (uint32_t) -1;

	int res = socket->write(buf, len);

	if(res == -2)
	{
		((EmulatorSession *) hook->hook.win->userdata)->yield();

		va_end(vl);
		return 0;
	}

	va_end(vl);
	return (uint32_t) res;
}


uint32_t hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	char * filename = va_arg(vl, char *);
	uint32_t res = ((EmulatorSession *) hook->hook.win->userdata)->createFile(filename);

	va_end(vl);
	return res;
}

uint32_t hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	uint32_t handle = va_arg(vl, uint32_t);
	uint8_t * buffer = va_arg(vl, uint8_t *);
	uint32_t length = va_arg(vl, uint32_t);

	if(!((EmulatorSession *) hook->hook.win->userdata)->appendFile(handle, buffer, length))
	{
		va_end(vl);
		return 0;
	}

	va_end(vl);
	return 1;
}

uint32_t hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	uint32_t handle = va_arg(vl, uint32_t);

	((EmulatorSession *) hook->hook.win->userdata)->closeHandle(handle);

	va_end(vl);
	return 0;
}


uint32_t hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	char * image = va_arg(vl, char *);
	char * cmdline = va_arg(vl, char *);

	((EmulatorSession *) hook->hook.win->userdata)->createProcess(image, cmdline);

	va_end(vl);
	return 0;
}

uint32_t hook_WinExec(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	va_list vl;
	va_start(vl, hook);

	char * cmdline = va_arg(vl, char *);

	((EmulatorSession *) hook->hook.win->userdata)->createProcess(cmdline, cmdline);

	va_end(vl);
	return 0;
}


}

