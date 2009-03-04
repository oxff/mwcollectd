/*
 * $Id: dispatcher.h 300 2006-02-06 01:09:06Z oxff $
 *
 */
 
#ifndef __MWCCORE_DISPATCHER_H
#define __MWCCORE_DISPATCHER_H

#include <list>
#include <map>
#include <string.h>

#include "log.h"

namespace mwccore
{
	class ShellcodeParser
	{
	public:
		virtual bool parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulRemoteHost, CorrelationId cid) = 0;
	};
	
	class ShellcodeDispatcher
	{
	public:
		ShellcodeDispatcher(const char * szStoreDirectory, bool bStoreAll);
		virtual ~ShellcodeDispatcher();
		
		virtual bool parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulRemoteHost, CorrelationId cid);
		
		virtual void registerParser(ShellcodeParser * pParser);
		virtual void unregisterParser(ShellcodeParser * pParser);
		
	private:		
		std::list<ShellcodeParser *> m_lpParsers;
		char * m_szShellcodeDirectory;
		bool m_bStoreAll;
	};
	
	
	
	class Downloader
	{
	public:
		virtual bool downloadFile(const char * szUrl, CorrelationId cid) = 0;
	};
	
	struct DownloaderMapComparator
	{
		bool operator()(const char* s1, const char* s2) const
		{
			return strcmp(s1, s2) < 0;
		}
	};
	
	class DownloadManager
	{
	public:
		DownloadManager(unsigned long t, bool bEmitAlerts);
		~DownloadManager();
		
		virtual bool downloadFile(const char * szUrl, CorrelationId cid);
		void cleanBlockings();
		
		virtual bool registerDownloader(Downloader * m_pDownloader, const char * szProtocol);
		virtual bool unregisterDownloader(const char * szProtocol);
	
	private:
		std::map<const char *, Downloader *, DownloaderMapComparator> m_mpDownloaders;
		std::map<const char *, unsigned long, DownloaderMapComparator> m_mulBlockings;
		
		bool m_bEmitAlerts;
		unsigned long m_ulBlockTime;
		unsigned long m_ulLastCleanup;
	};
	
	
	
	class Submitter
	{
	public:
		virtual bool submitData(const unsigned char * pData, unsigned int nLength, CorrelationId cid) = 0;
	};
	
	class SubmissionDispatcher
	{
	public:
		virtual void registerSubmitter(Submitter * pSubmitter);
		virtual void unregisterSubmitter(Submitter * pSubmitter);
		
		virtual bool submitData(const unsigned char * pData, unsigned int nLength, CorrelationId cid);
		
	protected:
		std::list<Submitter *> m_lpSubmitters;
	};
};

#endif // __MWCCORE_DISPATCHER_H
