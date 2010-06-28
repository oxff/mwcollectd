#				    _ _           _      _ 
#	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
#	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
#	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
#	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
#
#
# 	Copyright 2010 Georg Wicherski, <gw@mwcollect.org>
#
#
#	This file is part of mwcollectd.
#
#	mwcollectd is free software: you can redistribute it and/or modify
#	it under the terms of the GNU Lesser General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	mwcollectd is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU Lesser General Public License for more details.
#
#	You should have received a copy of the GNU Lesser General Public License
#	along with mwcollectd. If not, see <http://www.gnu.org/licenses/>.
#

from http.HttpConnection import HttpConnection
from mwcollectd import *

def start(config):
	global http_server
	http_server = NetworkServer(('any', 80), HttpConnection)

	return True


def stop():
	global http_server
	http_server.close()

	return True
