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


	// TODO FIXME: save bytecopy here plies

	/*void * pCaller    = */(void)va_arg(vl, void *);
	char * szURL      = va_arg(vl, char *);
	char * szFileName = va_arg(vl, char *);
	/*int    dwReserved = */(void)va_arg(vl, int   );
	/*void * lpfnCB     = */(void)va_arg(vl, void *);

	((EmulatorSession *) hook->hook.win->userdata)->addDirectDownload(szURL, szFileName);

	va_end(vl);
	return 0;
}


}

