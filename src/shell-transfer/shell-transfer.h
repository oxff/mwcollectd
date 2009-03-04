/*
 * Transfer Shell Commands Module (`tftp[.exe]', `ftp[.exe]')
 * $Id: shell-transfer.h 307 2006-02-07 15:12:05Z oxff $
 *
 * `Doubleshot Espresso please.'
 */
 
#ifndef __MWCMOD_SHELLTRANSFER_H
#define __MWCMOD_SHELLTRANSFER_H

#include <mwcollect/core.h>
using namespace mwccore;

#include <pcre.h>

class ShellTransferModule : public Module, public ShellParser
{
public:	
	ShellTransferModule() { }
	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	
	virtual bool parseCommand(const char * szLine, VirtualShell * pShell);
	
protected:
	bool parseFtpFile(const char * szFile, CorrelationId cid, const char * szRemoteHost);
	
protected:
	pcre * m_pTftpPattern;

	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
};

#endif //__MWCMOD_SHELLTRANSFER_H
