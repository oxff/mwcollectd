#
#				    _ _           _      _ 
#	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
#	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
#	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
#	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
#
#
# 	Copyright 2010 Georg Wicherski <gw@mwcollect.org>
#
#
#	This file is part of mwcollectd.
#
#	mwcollectd is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	mwcollectd is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU Lesser General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with mwcollectd. If not, see <http://www.gnu.org/licenses/>.
#
#
#	This SMB emulation was originally written for dionaea and is also
#	redistributed with mwcollectd. Unlike the rest of mwcollectd, this
#	code is licensed under the GPL.

from dionaea_compat import Logger
from mwcollectd import *

import traceback

def start():
	from .smb import smbd, epmapper
	
	global smb_server, epm_server
	smb_server = NetworkServer(('any', 445), smbd)
	epm_server = NetworkServer(('any', 135), epmapper)

	return True


def stop():
	global smb_server, epm_server
	smb_server.close()
	epm_server.close()

	return True
