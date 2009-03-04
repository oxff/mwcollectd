/*
 * This is a FileLogger wrapper module
 *
 * $Id: log-file.cpp 251 2005-12-09 09:10:17Z oxff $
 *
 */

#include "log-file.h"

#include <errno.h>
#include <string.h>


extern "C"
{
	void * CreateInstance()
	{
		return new LogFileModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (LogFileModule *) pInstance;
	}
}

LogFileModule::LogFileModule()
{
	m_pFileLogger = 0;
}

LogFileModule::~LogFileModule()
{
	stop(); // stop() performs check whether already stopped itself
}


bool LogFileModule::start()
{
	const char * szFileName = m_pConfig->getString(":logfile", "/var/log/mwcollect.log");
	const char * szLogTag = m_pConfig->getString(":filter", "all");	
	FILE * pFile;
	
	if(!(pFile = fopen(szFileName, "at")))
	{
		LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Could not open logfile \"%s\" for writing: %s!", szFileName, strerror(errno));
		return false;
	}
	
	m_pFileLogger = new FileLogger(pFile, true, szLogTag);
	g_pLogManager->registerLogFacility(m_pFileLogger);
	
	return true;
}

void LogFileModule::stop()
{
	if(m_pFileLogger)
	{
		g_pLogManager->unregisterLogFacility(m_pFileLogger);
		
		delete m_pFileLogger;
		m_pFileLogger = 0;
	}
}
