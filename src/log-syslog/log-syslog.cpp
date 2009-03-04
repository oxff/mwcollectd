/*
 * mwcollect Logging Module that logs to a POSIX 1003.1-2001 syslog facility.
 * Better late than never, requested for v3.x by securifo@web.de.
 *
 * $Id: log-syslog.cpp 271 2006-01-06 02:42:56Z oxff $
 *
 */
 
#include "log-syslog.h"
#include <syslog.h>

extern "C"
{	
	void * CreateInstance()
	{
		return new SyslogModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (SyslogModule *) pInstance;
	}
}


bool SyslogModule::start()
{
	m_pPattern = new LogTagPattern();
	
	if(!m_pPattern->parsePattern(m_pConfiguration->getString(":filter", "critical,shellcode,exploit,download")))
	{
		LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not parse syslog log tag pattern \"%s\"!", m_pConfiguration->getString(":filter", "critical,shellcode,exploit,download"));
		
		delete m_pPattern;
		return false;
	}
	
	g_pLogManager->registerLogFacility(this);
	openlog(m_pConfiguration->getString(":identity", "mwcollect"), LOG_NDELAY, LOG_DAEMON);
	
	DEBUG("Syslog module with identity \"%s\" started.", m_pConfiguration->getString(":identity", "mwcollect"));
	
	return true;
}

void SyslogModule::stop()
{
	closelog();
	
	g_pLogManager->unregisterLogFacility(this);
	
	delete m_pPattern;
}

void SyslogModule::log(LogTag ltTag, LogMessage * pMessage)
{
	if(!m_pPattern->testAgainst(ltTag))
		return;

	int iPriority;
	
	if(ltTag & LT_DEBUG)
		iPriority = LOG_DEBUG;
	else if(ltTag & LT_LEVEL_CRITICAL)
		iPriority = LOG_ALERT;
	else if(ltTag & LT_LEVEL_MEDIUM)
		iPriority = LOG_WARNING;
	else if(ltTag & LT_LEVEL_LOW)
		iPriority = LOG_NOTICE;
	else
		iPriority = LOG_INFO;
		
	syslog(iPriority, "%s", pMessage->renderString());
}
