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


#ifndef __MWCOLLECTD_SHELLCODELIBEMU_SCHOOKS_HPP
#define __MWCOLLECTD_SHELLCODELIBEMU_SCHOOKS_HPP

namespace schooks
{


uint32_t hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...);

uint32_t hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hook_WinExec(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...);

uint32_t hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...);

uint32_t hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hookspecial_connect(struct emu_env *env, struct emu_env_hook *hook);
uint32_t hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t hookspecial_accept(struct emu_env *env, struct emu_env_hook *hook);
uint32_t hookspecial_recv(struct emu_env *env, struct emu_env_hook *hook);
uint32_t hookspecial_send(struct emu_env *env, struct emu_env_hook *hook);


}

#endif // __MWCOLLECTD_SHELLCODELIBEMU_SCHOOKS_HPP
