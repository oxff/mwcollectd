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


// TODO FIXME: getpwnam and setrlimit HAVE_ checks
#include <sys/types.h>
#include <pwd.h>
// TODO FIXME: getgrnam HAVE_ checks
#include <grp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>
#include <errno.h>

#include <string>
using namespace std;


namespace mwcollectd
{


Daemon::Daemon(const char * configfile)
{
	string basepath = configfile;
	string::size_type pos;

	if((pos = basepath.rfind("/")) != string::npos)
	{
		basepath.erase(pos + 1, basepath.size());
	}
	else
		basepath = "";

	m_configBasepath = basepath;

	m_Configuration = new Configuration();

	try
	{
		m_Configuration->parseFile(configfile);
	}
	catch(const char * error)
	{
		printf("Parsing configuration file failed: %s\n", error);
		throw;
	}

	try
	{
		m_NameResolvingFacility = NameResolvingFacility::createFacility
			(&m_NetworkManager, &m_TimeoutManager);
	}
	catch(...)
	{
		puts("Unable to create name resolving facility from libnetworkd!");
		throw;
	}
}

Daemon::~Daemon()
{
	delete m_NameResolvingFacility;
	delete m_Configuration;
}

bool Daemon::run(char * changeUser)
{
	if(!start())
		return false;

	m_EventManager.setLogManager(&m_LogManager);

	if(changeUser)
	{
		char * changeGroup = strchr(changeUser, ':');
		struct passwd * changeUserInfo;
		struct group * changeGroupInfo;

		if(changeGroup)
			* changeGroup++ = 0;

		// TODO FIXME: getpwnam and setrlimit HAVE_ checks
		if(changeGroup)
		{
			if((changeGroupInfo = getgrnam(changeGroup)) != NULL)
			{
				if(setegid(changeGroupInfo->gr_gid) == -1)
				{
					perror("Failed to set effective group id");
					return false;
				}
			}
			else
			{
				perror("Could not resolve change group");
				return false;
			}
		}

		if((changeUserInfo = getpwnam(changeUser)) != NULL)
		{
			if(seteuid(changeUserInfo->pw_uid) == -1)
			{
				perror("Failed to set effective user id");
				return false;
			}
		}
		else
		{
			perror("Could not resolve change user");
			return false;
		}
	}

	for(;;)
	{
		m_active = true;
		
		while(m_active)
		{
			uint32_t timeout = m_TimeoutManager.deltaNext();

			if(m_HashManager.computationPending())
				timeout = 0;

			m_TimeoutManager.fireTimeouts();
			m_HashManager.loop();

			for(std::list<CoreLoopable *>::iterator it = m_loopables.begin();
				it != m_loopables.end(); ++it)
			{
				(* it)->loop();

				if((* it)->computationPending())
					timeout = 0;
			}

			if(timeout == (uint32_t) -1)
				timeout = 2;

			m_NetworkManager.waitForEventsAndProcess(timeout);
		}

		do
		{
			m_active = true;

			if(m_ModuleManager.unloadAll())
			{
				LOG(L_CRIT, "Clean shutdown complete!");
				return true;
			}
			
			LOG(L_SPAM, "Requested shutdown but some module could not"
				" cleanly unload, still loaded:");
				
			list<ModuleEncapsulation> modules;
			
			m_ModuleManager.enumerateModules(&modules);
			
			for(list<ModuleEncapsulation>::iterator it = modules.begin();
				it != modules.end(); ++ it)
			{
				LOG(L_SPAM, " [%x] %s, %s", it->moduleId,
					it->moduleInterface->getName(),
					it->moduleInterface->getDescription());
			}
		} while(!m_active);
	}
}

bool Daemon::start()
{
	string libraryPath;
	vector<string> modules;

	if(m_Configuration->getInteger(":max-fd", 0) > 0)
	{
		struct rlimit limit;

		limit.rlim_cur = limit.rlim_max = m_Configuration->getInteger(":max-fd",
			10240);

		// TODO FIXME: getpwnam and setrlimit HAVE_ checks
		if(setrlimit(RLIMIT_NOFILE, &limit) < 0)
		{
			LOG(L_CRIT, "Could not increase maximum open fd's to %u: %s",
				m_Configuration->getInteger(":max-fd", 10240),
				strerror(errno));
			return false;
		}
	}


	try
	{
		modules = m_Configuration->getStringList(":modules:autoload");
		libraryPath = m_Configuration->getString(":modules:library-path",
			"/usr/lib/botsnoopd");
	}
	catch(...)
	{
	}

		
	for(vector<string>::iterator i = modules.begin(); i != modules.end(); ++i)
	{
		string library, config;
		string::size_type delimiter;

		if((delimiter = i->find(":")) != i->npos)
		{
			library = i->substr(0, delimiter);
			config = i->substr(delimiter + 1, i->npos);

			if(* config.begin() != '/')
				config = m_configBasepath + config;
		}
		else
			library = * i;

		library = libraryPath + "/" + library;

		try
		{
			if(config.empty())
			{
				m_LogManager.logFormatMessage(L_SPAM, "Loading module "
					"%s with no configuration...", library.c_str());
			}
			else
			{
				m_LogManager.logFormatMessage(L_SPAM, "Loading module "
					"%s with configuration %s...",
					library.c_str(), config.c_str());
			}

			m_ModuleManager.loadModule(library.c_str(),
				config.c_str(), this);
		}
		catch(const char * error)
		{
			m_LogManager.logFormatMessage(L_CRIT,
				"Failed to load \"%s\": %s\n", library.c_str(), error);
			m_ModuleManager.unloadAll();
			return false;
		}
	}

	return true;
}


}

