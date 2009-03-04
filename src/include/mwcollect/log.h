/*
 * $Id: log.h 224 2005-11-08 20:19:46Z oxff $
 *
 * `Rotterdam Nightmare'
 */
 
#ifndef __MWCCORE_LOG_H
#define __MWCCORE_LOG_H

#include <list>
#include <stdio.h>


#define LT_LEVEL_LOW 1
#define LT_LEVEL_MEDIUM 2
#define LT_LEVEL_CRITICAL 4

#define LT_PARSING 8
#define LT_DOWNLOAD 16
#define LT_INTHEWILD 32
#define LT_EXPLOIT 64
#define LT_ASSERT 128
#define LT_STATUS 256
#define LT_NETWORK 512

#define LT_DEBUG 1024

#define LT_SHELLCODE 2048

#define LT_NONE 0
#define LT_ALL 0xFFFF


#define LOG(level, teformat...) g_pLogManager->log(level, teformat)

#ifdef _DEBUG
#define DEBUG(teformat...) g_pLogManager->log(LT_DEBUG, teformat)
#else
#define DEBUG(teformat...) {}
#endif


namespace mwccore
{
	typedef long long CorrelationId;
	typedef unsigned short LogTag;


	enum ClassfulLogType
	{
		CLT_GENERIC = 0,
	};
	
	
		
	struct ClassfulProperty
	{
		char * szName;
		unsigned char * pucValue;
		unsigned int nLength;
	};	
	
	class GenericClassfulReceiver
	{
	public:
		virtual void setProperty(const char * szProperty, const unsigned char * pucValue, unsigned int nValueLength) = 0;
		virtual void setCorrelationIdentifier(CorrelationId cid) = 0;
	};
	
		
	
	
	// basic log message class, more specialised message should be derived from
	class LogMessage
	{
	public:		
		virtual char * renderString() = 0; // attention, this has to be free'd afterwards
		virtual bool copyTo(GenericClassfulReceiver * pTarget)
		{ return false; }
	};
	
	
	
	
	class GenericClassfulLogMessage : public LogMessage, public GenericClassfulReceiver
	{
	public:
		GenericClassfulLogMessage(const char * szStringRepresentation, CorrelationId cid = 0);
		~GenericClassfulLogMessage();
		
		virtual char * renderString();
		
		virtual void setProperty(const char * szProperty, const unsigned char * pucValue, unsigned int nValueLength);
		virtual void setString(const char * szProperty, const char * szValue)
		{ setProperty(szProperty, (unsigned char *) szValue, strlen(szValue) + 1); }
		virtual void setAddress(const char * szProperty, unsigned long ulAddress);
		virtual void setInteger(const char * szProperty, int i);

		virtual bool copyTo(GenericClassfulReceiver * pTarget);
		virtual void setCorrelationIdentifier(CorrelationId cid)
		{ m_cid = cid; }
		
	private:
		std::list<ClassfulProperty> m_lcpProperties;
		CorrelationId m_cid;		
		char * m_szString;
	};


	// we use this one in the string-wrapper function
	class WrapperLogMessage : public LogMessage
	{
	public:
		WrapperLogMessage(const char * szMessage);
		virtual ~WrapperLogMessage();
		
		virtual char * renderString();
		
	protected:
		char * m_szCopy;
	};	
	
	
	class LogFacility
	{
	public:
		virtual void log(LogTag ltLevel, LogMessage * pMessage) = 0;
	};
	
	class LogTagPattern
	{
	public:
		LogTagPattern();
		virtual ~LogTagPattern();
		
		bool parsePattern(const char * szPattern);
		virtual bool testAgainst(LogTag ltTag);
		
	protected:
		LogTag parseTag(const char * szTag);
		
	private:
		std::list<LogTag> m_lltPattern;
	};
	
	class LogManager
	{
	public:
		LogManager();
		virtual ~LogManager();
		
		virtual void registerLogFacility(LogFacility * pLogFacility);
		virtual void unregisterLogFacility(LogFacility * pLogFacility);
		
		// this is only a helper function to ease the insertion of small log
		// statements or debug statements (-> macro)
		virtual void log(LogTag ltLevel, const char * szFormat, ...);

		// the preferred way to do things
		// log with string will only wrap around this
		virtual void log(LogTag ltlevel, LogMessage * pMessage);
		
		virtual CorrelationId generateCorrelationIdentifier();
		
	private:
		std::list<LogFacility *> m_lpFacilities;
	};
	
	class FileLogger : public LogFacility
	{
	public:
		FileLogger(FILE * pFile, bool bClose, const char * szTagPattern);
		virtual ~FileLogger();
		
		virtual void log(LogTag ltlevel, LogMessage * pMessage);
		
	private:
		LogTagPattern * m_pPattern;
		FILE * m_pFile;
		bool m_bClose;
	};
	
	extern LogManager * g_pLogManager;
};

#endif // __MWCCORE_LOG_H
