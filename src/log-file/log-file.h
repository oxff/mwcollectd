/*
 * This file lacks one of those cool lines in the header.
 *
 * $Id: log-file.h 50 2005-06-25 14:39:49Z oxff $
 *
 */

#ifndef __MWCMOD_LOGFILE_H
#define __MWCMOD_LOGFILE_H

#include <mwcollect/core.h>


using namespace mwccore;

class LogFileModule : public Module
{
public:
	LogFileModule();
	virtual ~LogFileModule();
	
	virtual bool start();
	virtual void stop();
	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfig = pConfig; }
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; }
	
private:
	Configuration * m_pConfig;
	MalwareCollector * m_pCollector;
	
	FileLogger * m_pFileLogger;
};


#endif // __MWCMOD_LOGFILE_H
