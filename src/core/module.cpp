/*
 * $Id: module.cpp 276 2006-01-07 18:33:36Z oxff $
 *
 * `Koerper sind nur Huellen.'
 *
 */
 
#include <mwcollect/core.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <list>

#if defined(LINUX_FLAVOURED) || defined(OBSD_FLAVOURED)
	#include <dlfcn.h>
#else
	#error I do not now a shared library header for you POSIX flavour!
#endif

namespace mwccore
{
	ModuleLister::ModuleLister()
	{
	}
	
	ModuleLister::~ModuleLister()
	{
		for(std::list<ModuleInfo>::iterator i = m_lmiInfo.begin(); i != m_lmiInfo.end(); ++i)
		{
			free((* i).szPath);
			free((* i).szConfig);
		}
	}
	
	bool ModuleLister::loadModule(const char * szModulePath, const char * szConfiguration)
	{
		ModuleInfo miInfo = { strdup(szModulePath), strdup(szConfiguration) };
		m_lmiInfo.push_back(miInfo);
		
		return true;
	}
	
	
	
	ModuleManager::ModuleManager(MalwareCollector * pCollector)
	{
		m_pCollector = pCollector;
	}
	
	ModuleManager::~ModuleManager()
	{
		unloadModules();
	}
	
	bool ModuleManager::loadModule(const char * szModule, const char * szConfig, bool bLate)
	{
		Module * (* fnCreateInstance)();
		Configuration * pConfig = new Configuration();
		ModuleInfo miInfo;
		
		miInfo.szPath = strdup(szModule);
		miInfo.szConfig = strdup(szConfig);
		
		if(!pConfig->parse(szConfig))
		{
			g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Parsing the configuration file \"%s\" for \"%s\" failed!", szConfig, szModule);
			return false;
		}
		
		#if defined(LINUX_FLAVOURED) || defined(OBSD_FLAVOURED)
			miInfo.pLibrary = dlopen(szModule, RTLD_NOW);
			
			if(!miInfo.pLibrary)
			{
				g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Loading the shared library \"%s\" failed: %s / %s!", szModule, strerror(errno), dlerror());
				
				free(miInfo.szPath);
				free(miInfo.szConfig);
				delete pConfig;
				
				return false;
			}
			
			(void * &) fnCreateInstance = dlsym(miInfo.pLibrary, "CreateInstance");
			
			if(!fnCreateInstance)
			{
				g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not get a symbol from \"%s\": %s / !", szModule, strerror(errno), dlerror());
				
				free(miInfo.szPath);
				free(miInfo.szConfig);
				delete pConfig;
				dlclose(miInfo.pLibrary);
				
				return false;
			}
		#else
			#error I do not know how to load a shared library in your POSIX flavour!
		#endif
		
		miInfo.pInstance = fnCreateInstance();
			
		if(!miInfo.pInstance)
		{
			g_pLogManager->log(LT_LEVEL_CRITICAL | LT_STATUS, "Could not create instance in \"%s\": %s!", szModule, strerror(errno));
			
			free(miInfo.szPath);
			free(miInfo.szConfig);
			delete pConfig;
			dlclose(miInfo.pLibrary);
			
			return false;
		}
		
		miInfo.pInstance->assignConfiguration(pConfig);
		miInfo.pInstance->assignCollector(m_pCollector);
		
		miInfo.pConfig = pConfig;
		
		m_lmiModules.push_back(miInfo);
		
		if(bLate)
			miInfo.pInstance->start();

		return true;
	}
	
	bool ModuleManager::unloadModules()
	{
		std::list<ModuleInfo>::iterator iNext;
		
		for(std::list<ModuleInfo>::iterator i = m_lmiModules.begin(); i != m_lmiModules.end(); i = iNext)
		{
			iNext = i;
			++iNext;
			
			// the following check (together with the paired looping) ensures that
			// the network interface modules are unloaded last
			// otherwise this would result in nasty segfaults when closing net connections
			// upon module ::stop()			
			if(m_pCollector->getNetworkCore()->interfaceModule(i->pInstance))
				continue;
		
			delete (* i).pInstance;
			delete (* i).pConfig;
			
			free((* i).szConfig);
			free((* i).szPath);
			
			#if defined(LINUX_FLAVOURED) || defined(OBSD_FLAVOURED)
				dlclose((* i).pLibrary);
			#else
				#error I do not know how to unload a shared library in your POSIX flavour!
			#endif
			
			m_lmiModules.erase(i);
		}
		
		for(std::list<ModuleInfo>::iterator i = m_lmiModules.begin(); i != m_lmiModules.end(); i = iNext)
		{
			delete (* i).pInstance;
			delete (* i).pConfig;
			
			free((* i).szConfig);
			free((* i).szPath);
			
			#if defined(LINUX_FLAVOURED) || defined(OBSD_FLAVOURED)
				dlclose((* i).pLibrary);
			#else
				#error I do not know how to unload a shared library in your POSIX flavour!
			#endif
		}
		
		
		m_lmiModules.clear();
		return true;
	}
	
	bool ModuleManager::unloadEarly(Module * pUnload)
	{
		for(std::list<ModuleInfo>::iterator i = m_lmiModules.begin(); i != m_lmiModules.end(); ++i)
		{
			if(i->pInstance == pUnload)
			{
				i->pInstance->stop();
				
				delete (i->pInstance);
				delete (i->pConfig);
				free(i->szPath);
				free(i->szConfig);
				dlclose(i->pLibrary);
				
				m_lmiModules.erase(i);
				return true;
			}
		}
		
		return false;
	}
	
	
	bool ModuleManager::startModules()
	{
		for(std::list<ModuleInfo>::iterator i = m_lmiModules.begin(); i != m_lmiModules.end(); ++i)
			if(!((* i).pInstance->start()))
			{
				LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Module \"%s\":\"%s\" failed to start up!", i->szPath, i->szConfig);
				
				return false;
			}
				
		return true;
	}
	
	void ModuleManager::stopModules()
	{
		// same paired loop for net interface modules as above
		
		for(std::list<ModuleInfo>::iterator i = m_lmiModules.begin(); i != m_lmiModules.end(); ++i)			
			if(!m_pCollector->getNetworkCore()->interfaceModule(i->pInstance))
				i->pInstance->stop();
		
		for(std::list<ModuleInfo>::iterator i = m_lmiModules.begin(); i != m_lmiModules.end(); ++i)			
			if(m_pCollector->getNetworkCore()->interfaceModule(i->pInstance))
				i->pInstance->stop();
	}
	
	void ModuleManager::loopModules()
	{
		for(std::list<ModuleInfo>::iterator i = m_lmiModules.begin(); i != m_lmiModules.end(); ++i)
			(* i).pInstance->loop();
	}
}
