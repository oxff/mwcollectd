/*
 * Shellcode parser for miscellaneous shellcodes found in the wild.
 * kkuehl was the first to provide one, thank you. Other tickets will be added later on.
 *
 * $Id: scparse-misc.h 208 2005-11-05 13:30:19Z oxff $
 *
 */
 
#ifndef __MWCMOD_SCPARSEMISC_H
#define __MWCMOD_SCPARSEMISC_H

#include <mwcollect/core.h>

#include <pcre.h>

using namespace mwccore;

class ParserModule : public Module, public ShellcodeParser
{
public:
	ParserModule();
	~ParserModule();
	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();

	virtual bool parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulHost, CorrelationId cid);
	
protected:
	 bool compilePatterns(pcre * * * pppPatterns, const char * * pszPatterns, unsigned int nPatterns);
	
private:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
	pcre * * m_ppPatterns;
};

#endif // __MWCMOD_SCPARSEMISC_H
