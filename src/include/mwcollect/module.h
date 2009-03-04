/*
 * $Id: module.h 50 2005-06-25 14:39:49Z oxff $
 *
 * `This is my boomstick!'
 */
 
#ifndef __MWCCORE_MODULE_H
#define __MWCCORE_MODULE_H

#include "core.h"

#include <list>

namespace mwccore
{
	class MalwareCollector;
	
	class Module	
	{
	public:
		virtual void assignConfiguration(Configuration * pConfig) = 0;
		virtual void assignCollector(MalwareCollector * pCollector) = 0;
		
		virtual bool start() = 0;
		virtual void loop() { }
		virtual void stop() = 0;
	};
	
	struct ModuleInfo
	{
		char * szPath;
		char * szConfig;
		
		Module * pInstance;
		void * pLibrary;
		Configuration * pConfig; // keep track of this for deleting later on
	};
	
	class ModuleLister : public ConfigurationDirectiveManager
	{
	public:
		ModuleLister();
		virtual ~ModuleLister();

		virtual bool loadModule(const char * szModulePath, const char * szConfiguration);
		
		std::list<ModuleInfo> m_lmiInfo;
	};
	
	class ModuleManager
	{
	public:
		ModuleManager(MalwareCollector * pCollector);
		~ModuleManager();
		
		bool loadModule(const char * szPath, const char * szConfig, bool bLate = false);
		bool unloadEarly(Module * pUnload);
		bool unloadModules();
		
		bool startModules();
		void loopModules();
		void stopModules();
		
	private:
		MalwareCollector * m_pCollector;
		LogManager * m_pLogManager;
		
		std::list<ModuleInfo> m_lmiModules;
	};
};

#endif // __MWCCORE_MODULE_H
