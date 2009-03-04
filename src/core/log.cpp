/*
 * Today's again a sunny summer day and I'm feeling happy! :D
 * $Id: log.cpp 244 2005-12-04 17:02:22Z oxff $
 *
 * `Now is the time!'
 *
 */
 
#include <mwcollect/core.h>

#include <string>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace mwccore
{
	LogManager * g_pLogManager;
	
	

	LogTagPattern::LogTagPattern()
	{
	}
	
	LogTagPattern::~LogTagPattern()
	{
	}
	
	bool LogTagPattern::parsePattern(const char * szPattern)
	{
		std::string sTag = std::string();
		LogTag ltMask = LT_NONE;
		
		m_lltPattern.clear();
		
		if(!strcmp(szPattern, "none"))
			return true;
		
		for(const char * c = szPattern; * c; ++c)
		{
			if(isspace(*c))
				continue;
					
			if(* c == '&' || * c == ',')
			{
				LogTag ltTag = parseTag(sTag.c_str());
				sTag.clear();
				
				if(* c == '&')
				{
					ltMask |= ltTag;
				}
				else if(* c == ',')
				{
					ltMask |= ltTag;
					
					if(ltMask != LT_ALL && ltMask != LT_NONE)
						m_lltPattern.push_back(ltMask);
					else if(ltMask == LT_ALL)
						m_lltPattern.push_back(0);
						
					ltMask = LT_NONE;
				}
				else
					return false;
			}
			else if(* c >= 'a' && * c <= 'z')
				sTag.push_back(* c);
			else
				return false;
		}
		
		{
			LogTag ltTag = parseTag(sTag.c_str());
			
			if(ltTag == LT_NONE)
			{
				LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Unknown tag: \"%s\"!", sTag.c_str());
				
				return false;
			}
			
			ltMask |= ltTag;
				
			if(ltMask != LT_ALL && ltMask != LT_NONE)
				m_lltPattern.push_back(ltMask);
			else if(ltMask == LT_ALL)
				m_lltPattern.push_back(0);
		}
		
		return true;
	}
	
	LogTag LogTagPattern::parseTag(const char * szTag)
	{
		static struct
		{
			const char * szTag;
			LogTag ltTag;
		} tagMap[] = 
		{
			{ "low", LT_LEVEL_LOW },
			{ "medium", LT_LEVEL_MEDIUM },
			{ "critical", LT_LEVEL_CRITICAL },
			
			{ "network", LT_NETWORK },
			{ "parsing", LT_PARSING },
			{ "download", LT_DOWNLOAD },
			{ "inthewild", LT_INTHEWILD },
			{ "exploit", LT_EXPLOIT },
			{ "assert", LT_ASSERT },
			{ "status", LT_STATUS },
			
			{ "debug", LT_DEBUG },
			
			{ "shellcode", LT_SHELLCODE },
			
			{ "all", LT_ALL },
			{ 0, 0 },
		};
		
		for(int i = 0; tagMap[i].szTag; ++i)
		{
			if(!strcmp(tagMap[i].szTag, szTag))
				return tagMap[i].ltTag;
		}
		
		return LT_NONE;
	}
	
	bool LogTagPattern::testAgainst(LogTag ltTag)
	{		
		for(std::list<LogTag>::iterator i = m_lltPattern.begin(); i != m_lltPattern.end(); ++i)
			if((* i) == ((* i) & ltTag))
				return true;
				
		return false;
	}
	
	
	
	LogManager::LogManager()
	{
	}
	
	LogManager::~LogManager()
	{
	}
	
	void LogManager::registerLogFacility(LogFacility * pFacility)
	{
		m_lpFacilities.push_back(pFacility);
	}
	
	void LogManager::unregisterLogFacility(LogFacility * pFacility)
	{
		m_lpFacilities.remove(pFacility);
	}
	
	void LogManager::log(LogTag ltLevel, const char * szFormat, ...)
	{
		char * szMessage;
	
		{
			va_list vaParameters;
			
			va_start(vaParameters, szFormat);
			
			if(vasprintf(&szMessage, szFormat, vaParameters) < 0)
				return;
				
			va_end(vaParameters);
		}
		
		WrapperLogMessage wlmMessage = WrapperLogMessage(szMessage);
		
		log(ltLevel, &wlmMessage);	
				
		free(szMessage);
	}
	
	void LogManager::log(LogTag ltLevel, LogMessage * pMessage)
	{
		for(std::list<LogFacility *>::iterator i = m_lpFacilities.begin(); i != m_lpFacilities.end(); ++i)
			(* i)->log(ltLevel, pMessage);
	}
	
	CorrelationId LogManager::generateCorrelationIdentifier()
	{
		CorrelationId cid;
		
		cid = rand();
		cid |= ((CorrelationId) (time(0) & 0xFFFF)) << 32;
		cid |= ((CorrelationId) (rand() & 0xFFFF)) << 48;
		
		return cid;
	}
	
	
	
	FileLogger::FileLogger(FILE * pFile, bool bClose, const char * szLogPattern)
	{
		m_pFile = pFile;
		m_bClose = bClose;
		
		if(szLogPattern)
		{		
			m_pPattern = new LogTagPattern();
			
			if(!m_pPattern->parsePattern(szLogPattern))
			{
				delete(m_pPattern);
				m_pPattern = 0;
			}
		}
		else
			m_pPattern = 0;
	}
	
	FileLogger::~FileLogger()
	{
		if(m_pPattern)
			delete m_pPattern;
			
		if(m_bClose)
			fclose(m_pFile);
	}
	
	void FileLogger::log(LogTag ltLevel, LogMessage * pLogMessage)
	{
		struct tm t;
		time_t tStamp;
		char * szRendered, * szMessage;
		
		if(!m_pPattern || !m_pPattern->testAgainst(ltLevel))
			return;
			
		time(&tStamp);
		localtime_r(&tStamp, &t);
		
		szMessage = pLogMessage->renderString();		
		asprintf(&szRendered, "[%04d-%02d-%02d %02d:%02d:%02d] %s\r\n", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, szMessage);
		
		fputs(szRendered, m_pFile);
		free(szRendered);
		free(szMessage);
	}
	
	
	
	WrapperLogMessage::WrapperLogMessage(const char * szMessage)
	{
		m_szCopy = strdup(szMessage);
	}
	
	WrapperLogMessage::~WrapperLogMessage()
	{
		free(m_szCopy);
	}
	
	char * WrapperLogMessage::renderString()
	{
		return strdup(m_szCopy); // we have to duplicate again here since it is mandatory to free(..) the result
	}
	
	
	
	GenericClassfulLogMessage::GenericClassfulLogMessage(const char * szString, CorrelationId cid)
	{
		m_szString = strdup(szString);
		m_cid = cid;
	}
	
	GenericClassfulLogMessage::~GenericClassfulLogMessage()
	{
		free(m_szString);
		
		for(std::list<ClassfulProperty>::iterator i = m_lcpProperties.begin(); i != m_lcpProperties.end(); ++i)
		{
			free(i->szName);
			free(i->pucValue);
		}
	}
	
	char * GenericClassfulLogMessage::renderString()
	{
		return strdup(m_szString);
	}
	
	void GenericClassfulLogMessage::setProperty(const char * szProperty, const unsigned char * pucValue, unsigned int nValueLength)
	{
		ClassfulProperty cpProperty;
		
		cpProperty.szName = strdup(szProperty);
		cpProperty.pucValue = (unsigned char *) malloc(nValueLength);
		memcpy(cpProperty.pucValue, pucValue, nValueLength);
		cpProperty.nLength = nValueLength;
		
		m_lcpProperties.push_back(cpProperty);
	}
	
	void GenericClassfulLogMessage::setAddress(const char * szProperty, unsigned long ulHost)
	{
		struct in_addr iaAddress;
		
		iaAddress.s_addr = ulHost;
		
		setString(szProperty, inet_ntoa(iaAddress));
	}
	
	bool GenericClassfulLogMessage::copyTo(GenericClassfulReceiver * pTarget)
	{
		for(std::list<ClassfulProperty>::iterator i = m_lcpProperties.begin(); i != m_lcpProperties.end(); ++i)
			pTarget->setProperty(i->szName, i->pucValue, i->nLength);
		
		pTarget->setCorrelationIdentifier(m_cid);
		
		return true;
	}
	
	void GenericClassfulLogMessage::setInteger(const char * szProperty, int i)
	{
		char * szInt;
		
		asprintf(&szInt, "%i", i);
		setString(szProperty, szInt);
		free(szInt);
	}
}
