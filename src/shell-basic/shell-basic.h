/*
 * Basic Shell Commands Module (`echo', `*.bat' and `del')
 * $Id: shell-basic.h 111 2005-09-24 15:24:44Z oxff $
 *
 * `Doubleshot Espresso please.'
 */
 
#ifndef __MWCMOD_SHELLBASIC_H
#define __MWCMOD_SHELLBASIC_H

#include <mwcollect/core.h>
using namespace mwccore;

class ShellBasicModule : public Module, public ShellParser
{
public:	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	
	virtual bool parseCommand(const char * szLine, VirtualShell * pShell);
	
protected:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
};

#endif //__MWCMOD_SHELLBASIC_H
