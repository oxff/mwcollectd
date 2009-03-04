/*
 * mwcollect Logging Module that logs to a POSIX 1003.1-2001 syslog facility.
 * Better late than never, requested for v3.x by securifo@web.de.
 *
 * $Id: log-syslog.h 271 2006-01-06 02:42:56Z oxff $
 *
 */
 
#ifndef __MWCMOD_LOGSYSLOG_H
#define __MWCMOD_LOGSYSLOG_H

#include <mwcollect/core.h>
using namespace mwccore;


class SyslogModule : public Module, LogFacility
{
public:	
	virtual bool start();
	virtual void stop();
	
	virtual void log(LogTag ltLevel, LogMessage * pMessage);
	
	virtual void assignCollector(MalwareCollector * pCollector)
	{ m_pCollector = pCollector; }
	
	virtual void assignConfiguration(Configuration * pConfiguration)
	{ m_pConfiguration = pConfiguration; }
	
private:
	MalwareCollector * m_pCollector;
	Configuration * m_pConfiguration;
	
	LogTagPattern * m_pPattern;
};

#endif //__MWCMOD_LOGSYSLOG_H
