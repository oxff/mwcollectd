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

#include <mwcollectd.hpp>

#include <stdio.h>
#include <unistd.h>
#include <signal.h>


using namespace mwcollectd;


#define LOGO \
	"			            _ _           _      _ \n" \
	"	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |\n" \
	"	| '_ ` _ \\ \\ /\\ / / __/ _ \\| | |/ _ \\/ __| __/ _` |\n" \
	"	| | | | | \\ V  V / (_| (_) | | |  __/ (__| || (_| |\n" \
	"	|_| |_| |_|\\_/\\_/ \\___\\___/|_|_|\\___|\\___|\\__\\__,_|\n\n" \
	"	Copyright 2009 Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>\n" \
	"	This program is licensed under the GNU Lesser General Public License.\n"


void sigint_handler(int signal)
{
	g_daemon->stop();
}

int main(int argc, char * argv[])
{
	const char * configPath = CFGPREFIX "/etc/mwcollectd/mwcollectd.conf";
	const char * changeUser = 0;
	bool backgroundDaemon = true;

	char option;

	puts(LOGO);

	while((option = getopt(argc, argv, "c:u:hl")) != -1)
	{
		switch(option)
		{
			case '?':
			case 'h':
				printf("Usage: %s [options]\nThe supported options are:\n"
					"  -c <path>\t\tspecify the path to the configuration file\n"
					"  -u <user>[:<group>]\tdrop privilegues after initialization\n"
					"  -l\t\t\tlog to console and do not go into background\n"
					"  -h\t\t\tdisplay this help message\n",
					argv[0]);
				return 0;

			case 'l':
				backgroundDaemon = false;
				break;

			case 'c':
				configPath = optarg;
				break;

			case 'u':
				changeUser = optarg;
				break;
		}
	}

	try
	{
		Daemon daemon = Daemon(configPath);
		g_daemon = &daemon;

		if(backgroundDaemon)
		{
			if(::daemon(0, 0) < 0)
			{
				perror("daemon(..)'ize");
				return -1;
			}
		}
		else
			daemon.getLogManager()->addLogFacility(new FileLogger(stdout));

		signal(SIGINT, sigint_handler);

		if(!daemon.run())
		{
			if(!backgroundDaemon)
				puts("Daemon startup failed.");

			return -1;
		}
	}
	catch(...)
	{
		return -1;
	}

	return 0;
}

namespace mwcollectd
{
	Daemon * g_daemon;
}

