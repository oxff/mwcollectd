/*
 *  mwcollect v3 core include-all-or-nothing header
 *  written while listening to HardCore music, blasting my ears =D
 *  dedicated to Dorothea Reiffer, Palmstorem and all HardCore ravers in the world
 *
 *  see the file LICENSE for the LICENSE (if not already obivous enough)
 *
 *  $Id: core.h 287 2006-01-19 13:24:50Z oxff $
 *
 */

#ifndef __MWCCORE_MWCCORE_H
#define __MWCCORE_MWCCORE_H

#include "config.h"
#include "log.h"
#include "network.h"
#include "module.h"
#include "dispatcher.h"
#include "vshell.h"
#include "event.h"

namespace mwccore
{	
	class MalwareCollector
	{
	public:	
		static int run(int iArgC, char * szArgV[]);
		
		MalwareCollector();
		virtual ~MalwareCollector();

		
		void assignConfiguration(Configuration * pConfiguration);
		
		bool start();
		void loop();
		void stop();
		bool active() { return m_fActive; }
		
		virtual NetworkCore * getNetworkCore();
		virtual ShellcodeDispatcher * getShellcodeDispatcher();
		virtual DownloadManager * getDownloadManager();
		virtual ShellManager * getShellManager();
		virtual ModuleManager * getModuleManager();
		virtual SubmissionDispatcher * getSubmissionDispatcher();
		virtual EventDispatcher * getEventDispatcher();
		
		virtual void shutdown()
		{ m_fActive = false; }
		
	protected:
		bool initializeModules(ModuleLister * pLister, const char * szBinaryBase, const char * szConfigBase);
		
	private:
		ModuleManager * m_pModuleManager;
		Configuration * m_pConfiguration;
		
		NetworkCore * m_pNetworkCore;
		ShellcodeDispatcher * m_pShellcodeDispatcher;
		DownloadManager * m_pDownloadManager;
		ShellManager * m_pShellManager;
		SubmissionDispatcher * m_pSubmissionDispatcher;
		EventDispatcher * m_pEventDispatcher;
		
		bool m_fActive;
	};
};

#endif // __MWCCORE_MWCCORE_H
