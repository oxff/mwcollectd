/*
 * The one and only mwcollect!
 * $Id: mwcollect.cpp 308 2006-02-07 16:41:33Z oxff $
 *
 * `Get up and dance!'
 *
 */

#include <mwcollect/core.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#ifdef LINUX_FLAVOURED

// bind to interface on linux
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// end bind to if


#ifndef __NO_CAPABILITY
#undef _POSIX_SOURCE
#include <sys/capability.h>
#endif

#endif


// for the bind address option
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


mwccore::MalwareCollector * g_pCollector;

int main(int iArgC, char * szArgV[])
{
	srand(time(0)); // omg, not only a valid oop wrapper but also initialises random seed. NOOO!!!! :D
	
	return mwccore::MalwareCollector::run(iArgC, szArgV);
}

void signalhandler(int iSignal)
{
	if(iSignal != SIGINT)
		mwccore::g_pLogManager->log(LT_STATUS | LT_LEVEL_CRITICAL, "Died because of signal %i!", iSignal);
	else
		mwccore::g_pLogManager->log(LT_STATUS | LT_LEVEL_MEDIUM, "Exit requested with SIGINT.");

	if(g_pCollector->active())
		g_pCollector->shutdown();
	else
		exit(0);
}

void usage(FILE * pOutput, const char * szBinary)
{
	fprintf(pOutput,
	"mwcollect " MWCD_VERSION "\r\n$Id: mwcollect.cpp 308 2006-02-07 16:41:33Z oxff $\r\n\r\n"
	"Usage:\r\n"
	"%s [--version | --help | [--console-log [=tagpattern]] [--daemon]\r\n\t"
	"[--pid-file=/var/run/mwcollect.pid] [--user=nobody] [--capabilities]\r\n\t"
	"[--chroot=/opt/mwcollect/chroot] [--config=/etc/mwcollectd.conf]\r\n\t"
	"[--load-url=<url2test>] [--parse-shellcode=<file-with-shellcode>]\r\n\r\n"
	"See the man page for detailed parameter description.\r\n",
	szBinary);
}

namespace mwccore
{
	int MalwareCollector::run(int iArgC, char * szArgV[])
	{
		const char * szConfig = "/etc/mwcollect/mwcollectd.conf";
		bool bDaemon = false;
		bool bCaps = false;
		const char * szPidFile = "./mwcollectd.pid";
		const char * szChroot = 0;
		const char * szChuid = 0;
		const char * szTestShellcode = 0;
		const char * szTestUrl = 0;
		uid_t uid = 0;
		pid_t pid;
		
		g_pLogManager = new LogManager();
		MalwareCollector * pCollector = new MalwareCollector();
		ModuleLister * pLister = new ModuleLister();
		
		{
			int iValue;
			
			static option pOptions[] =
			{
				{ "donators", 0, 0, 'd' },
				{ "version", 0, 0, 'v' },
				{ "help", 0, 0, 'h' },
				{ "config", 1, 0, 'c' },
				{ "console-log", 2, 0, 'C' },
				{ "daemon", 0, 0, 'D' },
				{ "pid-file", 2, 0, 'P' },
				{ "user", 1, 0, 'u' },
				{ "capabilities", 0, 0, 'A' }, 
				{ "chroot", 1, 0, 'r' },
				
				{ "load-url", 2, 0, 'U' },
				{ "parse-shellcode", 2, 0, 'S' },
				{ 0, 0, 0, 0 }
			};
			
			opterr = 0;
			
			while((iValue = getopt_long(iArgC, szArgV, "vhc:C:DP:", pOptions, 0)) != -1)
			{
				switch(iValue)			
				{
					case 'c':
						szConfig = optarg;
						break;
						
					case 'C':
						g_pLogManager->registerLogFacility(new FileLogger(stdout, false, optarg));
						break;
						
					case 'D':
						bDaemon = true;
						break;
						
					case 'P':
						if(optarg)
							szPidFile = optarg;
						else
							szPidFile = "/var/run/mwcollectd.pid";
							
						break;
						
					case 'u':
						szChuid = optarg;
						break;
					
					case 'A':
						bCaps = true;
						break;
						
					case 'r':
						szChroot = optarg;
						break;
						
					case 'S':
						szTestShellcode = optarg;
						break;
						
					case 'U':
						szTestUrl = optarg;
						break;
						
					case 'd':
						printf("Check out http://www.mwcollect.org/wiki/Info/Donating for donating.\r\n"
							"The following People have donated money to the mwcollect project so far:\r\n\r\n"
							"Kane Lightowler (2005-06-20)\r\n"
							"\r\n");
						
					case 'v':
						printf("mwcollect " MWCD_VERSION "\r\n$Id: mwcollect.cpp 308 2006-02-07 16:41:33Z oxff $\r\nFlavour: " POSIX_FLAVOUR "\r\n\r\n(c) 2005-2006 by Honeynet Project, developed by Georg Wicherski\r\nDedicated to Dorothea Reiffer, Palmstroem and all Hardcore ravers in the world!\r\n");
						return 0;
					
					case 'h':
					default:
						usage(stderr, szArgV[0]);
						return 0;
				}
			}
		}
		
		{
			g_pCollector = pCollector;
			
			signal(SIGSEGV, signalhandler);
			signal(SIGILL, signalhandler);			
			signal(SIGHUP, signalhandler);
			signal(SIGTERM, signalhandler);
			signal(SIGINT, signalhandler);
		}
		
		{
			Configuration * pConfiguration = new Configuration(pLister);
			
			if(!pConfiguration->parse(szConfig))
			{
				g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Parsing configuration file failed, aborting!");
				exit(3);
			}
			
			pCollector->assignConfiguration(pConfiguration);
		}
		
		{
			{
				char * szBinaryBase, * szConfigBase;
				bool bFreeBinary = false, bFreeConfig = false;
				
				if(strrchr(szArgV[0], '/'))
				{
					szBinaryBase = (char *) malloc(strlen(szArgV[0]) + sizeof("/modules"));
				
					assert(szBinaryBase);
					
					strcpy(szBinaryBase, szArgV[0]);
					* strrchr(szBinaryBase, '/') = 0;
					strcat(szBinaryBase, "/modules");
					
					bFreeBinary = true;
				}
				else
					szBinaryBase = ".";
					
				if(strrchr(szConfig, '/'))
				{				
					szConfigBase = (char *) malloc((strrchr(szConfig, '/') - szArgV[0]) + sizeof("/modules"));
				
					if(!szConfigBase)
						return 0;
					
					strcpy(szConfigBase, szConfig);
					* strrchr(szConfigBase, '/') = 0;
					
					bFreeConfig = true;
				}
				else
					szConfigBase = ".";
				
				if(!pCollector->initializeModules(pLister, szBinaryBase, szConfigBase))
				{
					g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Loading initial modules failed, aborting!");
					exit(2);
				}
				
				if(bFreeBinary)
					free(szBinaryBase);
					
				if(bFreeConfig)				
					free(szConfigBase);
			}
			
			if(!pCollector->start())
			{
				g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Startup failed, aborting!");
				
				delete pCollector;
				delete g_pLogManager;
				
				return -1;
			}
			
			if(szChuid)
			{ // needs to be done before chrooting
				passwd * pPasswd;				
				errno = 0;
				
				if(!(pPasswd = getpwnam(szChuid)))
				{
					g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not map \"%s\" to an UID (%s)!", szChuid, strerror(errno));
					exit(5);
				}
				
				uid = pPasswd->pw_uid;
			}
			
			if(szChroot)
			{
				if(chdir(szChroot) < 0)
				{
					g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not change working directory to \"%s\"!", szChroot);	
					exit(1);
				}
				
				if(chroot(szChroot) < 0)
				{
					g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not chroot to %s!", szChroot);
					exit(1);
				}
				
				if(chdir("/") < 0)
				{
					g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not change working directory to \"/\" after chroot!", szChroot);
					exit(1);
				}
			}
		}
		
		{
			if(bDaemon && (pid = fork()))
			{
				FILE * pPidFile = fopen(szPidFile, "wt");
				
				if(!pPidFile)
				{
					LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Could not open %s for writing (PID)!", szPidFile);
					return 0;
				}
				
				fprintf(pPidFile, "%u", pid);
				fclose(pPidFile);
				
				return 0;
			}
					
			if(szChuid)
			{			
				#if defined(LINUX_FLAVOURED) && !defined(__NO_CAPABILITY)
				DEBUG("Changing UID to %s (%i) %s setting capabilties.", szChuid, (int) uid, bCaps ? "with" : "without");
				
				if(bCaps)
				{ // we still may need to bind ports < 1024 / create raw sockets
					cap_t capCapabilities = cap_init();
					cap_value_t cvValues[] = { CAP_NET_RAW, CAP_NET_BIND_SERVICE, CAP_SETUID };
					
					cap_set_flag(capCapabilities, CAP_PERMITTED, sizeof(cvValues) / sizeof(cap_value_t), cvValues, CAP_SET);
					cap_set_flag(capCapabilities, CAP_INHERITABLE, sizeof(cvValues) / sizeof(cap_value_t), cvValues, CAP_SET);
					cap_set_flag(capCapabilities, CAP_EFFECTIVE, sizeof(cvValues) / sizeof(cap_value_t), cvValues, CAP_SET);
					
					if(capsetp(getpid(), capCapabilities))
					{
						g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Coult not set capabilities before changing user id: %s!", strerror(errno));
						exit(5);
					}
				}
				else
					LOG(LT_STATUS | LT_LEVEL_CRITICAL, "You drop privilegues without setting capabilities beforehand! See http://www.mwcollect.org/wiki/Capabilities for further instructions.");
				#else
				DEBUG("Changing UID to %s (%i) without setting capabilties.", szChuid, (int) uid);
				#endif
				
				if(setresuid(uid, uid, uid) < 0)
				{
					g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not set effictive user id to %u: %s!", uid, strerror(errno));
					exit(5);
				}	
			}
			
			g_pLogManager->log(LT_LEVEL_MEDIUM | LT_STATUS, "mwcollect " MWCD_VERSION " up and running.");
			
			if(szTestShellcode)
			{
				FILE * pShellcodeFile;
				
				if(!(pShellcodeFile = fopen(szTestShellcode, "rb")))
					g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not open test shellcode file %s!", szTestShellcode);
				else
				{
					struct stat stShellcode;
					char * pShellcode;
					
					g_pLogManager->log(LT_LEVEL_LOW | LT_STATUS, "Loading test shellcode file %s.", szTestShellcode);
					
					stat(szTestShellcode, &stShellcode);
					pShellcode = (char *) malloc(stShellcode.st_size);
					fread(pShellcode, 1, stShellcode.st_size, pShellcodeFile);
					fclose(pShellcodeFile);
					
					if(pCollector->getShellcodeDispatcher()->parseShellcode((unsigned char *) pShellcode, stShellcode.st_size, 0x0100007F, g_pLogManager->generateCorrelationIdentifier()))
						g_pLogManager->log(LT_LEVEL_MEDIUM | LT_STATUS | LT_SHELLCODE, "Parsing test shellcode successful.");
					else
						g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS | LT_SHELLCODE, "Parsing test shellcode unsuccessful!");
						
					free(pShellcode);
				}
			}
			
			if(szTestUrl)
			{
				g_pLogManager->log(LT_LEVEL_LOW | LT_STATUS, "Downloading test URL %s.", szTestUrl);
				pCollector->getDownloadManager()->downloadFile(szTestUrl, g_pLogManager->generateCorrelationIdentifier());
			}
		}
	
		{	
			while(pCollector->active())
				pCollector->loop();
				
			DEBUG("Collector deactivated, stopping.");
			
			pCollector->stop();
			
			DEBUG("Stopped.");
			
			delete pCollector;
			delete g_pLogManager;
		}
		
		exit(0);
	}
	
	
	
	MalwareCollector::MalwareCollector()
	{
		m_pNetworkCore = new NetworkCore();
		m_pShellManager = new ShellManager(this);
		m_pSubmissionDispatcher = new SubmissionDispatcher();	
	}
	
	MalwareCollector::~MalwareCollector()
	{
		delete m_pDownloadManager;
		delete m_pNetworkCore;
		delete m_pShellManager;
		delete m_pSubmissionDispatcher;
	}
	
	void MalwareCollector::assignConfiguration(Configuration * pConfig)
	{
		m_pConfiguration = pConfig;
	}
	
	NetworkCore * MalwareCollector::getNetworkCore()
	{
		return m_pNetworkCore;
	}
	
	ModuleManager * MalwareCollector::getModuleManager()
	{
		return m_pModuleManager;
	}
	
	ShellcodeDispatcher * MalwareCollector::getShellcodeDispatcher()
	{
		return m_pShellcodeDispatcher;
	}
	
	DownloadManager * MalwareCollector::getDownloadManager()
	{
		return m_pDownloadManager;
	}
	
	ShellManager * MalwareCollector::getShellManager()
	{
		return m_pShellManager;
	}
	
	SubmissionDispatcher * MalwareCollector::getSubmissionDispatcher()
	{
		return m_pSubmissionDispatcher;
	}
	
	EventDispatcher * MalwareCollector::getEventDispatcher()
	{
		return m_pEventDispatcher;
	}
	
	bool MalwareCollector::initializeModules(ModuleLister * pLister, const char * szBinaryBase, const char * szConfigBase)
	{
		char * szPath, * szConfig;
		m_pModuleManager = new ModuleManager(this);
		
		for(std::list<ModuleInfo>::iterator i = pLister->m_lmiInfo.begin(); i != pLister->m_lmiInfo.end(); ++i)
		{
			{
				if((* i).szPath[0] == '/')
					szPath = (* i).szPath;
				else
					asprintf(&szPath, "%s/%s", szBinaryBase, (* i).szPath);
				
				if((* i).szConfig[0] == '/')
					szConfig = (* i).szConfig;
				else
					asprintf(&szConfig, "%s/%s", szConfigBase, (* i).szConfig);
			}
						
			if(!m_pModuleManager->loadModule(szPath, szConfig))
				return false;
				
			{
				if((* i).szPath != szPath)
					free(szPath);
					
				if((* i).szConfig != szConfig)
					free(szConfig);
			}
		}
		
		return true;
	}
	
	
	bool MalwareCollector::start()
	{
		m_fActive = true;
		
		m_pDownloadManager = new DownloadManager(m_pConfiguration->getLong(":download-blocking", 600), m_pConfiguration->getLong(":download-alerts", 1));
		
		{
			const char * szShellcodeDirectory = m_pConfiguration->getString(":shellcode-directory", "(none)");
			bool bStoreAllShellcodes = m_pConfiguration->getLong(":store-shellcodes", 0) != 0;

			if(!strcmp(szShellcodeDirectory, "(none)"))
				szShellcodeDirectory = 0;
		
			m_pShellcodeDispatcher = new ShellcodeDispatcher(szShellcodeDirectory, bStoreAllShellcodes);
		}
		
		{
			const char * szBindAddress = m_pConfiguration->getString(":bind-address", "0.0.0.0");
			
			#ifdef LINUX_FLAVOURED
			if(!strncmp(szBindAddress, "if:", 3))
			{
				int iSocket = socket(AF_INET, SOCK_STREAM, 0);
				struct ifreq ifrInterfaceRequest;
				struct sockaddr_in addrInterface;
				
				strncpy(ifrInterfaceRequest.ifr_name, szBindAddress + 3, IFNAMSIZ - 1);
				
				if(iSocket < 0 || ioctl(iSocket, SIOCGIFADDR, &ifrInterfaceRequest) < 0)
				{
					LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Failed to obtain address for interface %s: %s!", szBindAddress + 3, strerror(errno));
					
					return false;
				}
				
				memcpy(&addrInterface, &	(ifrInterfaceRequest.ifr_addr), sizeof(addrInterface));
				LOG(LT_LEVEL_LOW | LT_STATUS, "Obtained address of interface %s: %s", szBindAddress + 3, inet_ntoa(addrInterface.sin_addr));
				m_pNetworkCore->setBindAddress(addrInterface.sin_addr.s_addr);
			}
			else
			#endif
				m_pNetworkCore->setBindAddress(inet_addr(szBindAddress));
			
			m_pNetworkCore->setConnectionTimeout(m_pConfiguration->getLong(":connection-timeout", 0));
		}
		
		m_pEventDispatcher = new EventDispatcher();
		
		if(!m_pModuleManager->startModules())
			return false;
		
		return true;
	}
	
	void MalwareCollector::stop()
	{
		m_fActive = false;
		
		m_pModuleManager->stopModules();
		delete m_pModuleManager;
		
		delete m_pShellcodeDispatcher;
		delete m_pEventDispatcher;
	}
	
	void MalwareCollector::loop()
	{
		m_pDownloadManager->cleanBlockings();
		m_pModuleManager->loopModules();
		
		if(m_pNetworkCore->waitForEvents())
			m_pNetworkCore->loop();
	}
};
