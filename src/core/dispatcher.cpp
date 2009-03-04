/*
 * Sitting in La Colle sur Loup near Nizza in France, bright sunny day.
 * $Id: log.cpp 83 2005-09-02 13:47:47Z oxff $
 *
 * `Jump... Jump... Jump to the bassdrum!'
 *
 */

#include <mwcollect/core.h>

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>

namespace mwccore
{
	DownloadManager::DownloadManager(unsigned long t, bool bEmitAlerts)
	{
		m_ulBlockTime = t;
		m_ulLastCleanup = time(0);
		
		m_bEmitAlerts = bEmitAlerts;
	}
	
	DownloadManager::~DownloadManager()
	{
		for(std::map<const char *, unsigned long, DownloaderMapComparator>::iterator i = m_mulBlockings.begin(); i != m_mulBlockings.end(); ++i)		
			free((char *) i->first);
	}
	
	bool DownloadManager::downloadFile(const char * szUrl, CorrelationId cid)
	{
		std::map<const char *, Downloader *, DownloaderMapComparator>::iterator itDownloader;
		std::map<const char *, unsigned long, DownloaderMapComparator>::iterator itBlocking;
		
		itBlocking = m_mulBlockings.find(szUrl);
		
		if(itBlocking != m_mulBlockings.end())
		{
			if(itBlocking->second <= time(0))
			{
				free((void *) itBlocking->first);
				
				m_mulBlockings.erase(itBlocking);
			}
			else
			{
				DEBUG("URL \"%s\" blocked for %u more seconds.", szUrl, itBlocking->second - time(0));
				itBlocking->second = time(0) + m_ulBlockTime;
				
				return false;
			}
		}
		else
			m_mulBlockings[strdup(szUrl)] = time(0) + m_ulBlockTime;
		
		{
			const char * szBehindProtocol = strstr(szUrl, "://");
			char * szProtocol;
			
			if(!szBehindProtocol)
				return false;
				
			szProtocol = (char *) malloc(szBehindProtocol - szUrl + 1);
			strncpy(szProtocol, szUrl, szBehindProtocol - szUrl);
			szProtocol[szBehindProtocol - szUrl] = 0;
			
			itDownloader = m_mpDownloaders.find(szProtocol);
			free(szProtocol);
		}
		
		if(itDownloader == m_mpDownloaders.end())
		{
			LOG(LT_DOWNLOAD | LT_STATUS | LT_LEVEL_CRITICAL | LT_INTHEWILD, "Found no handler for URL \"%s\"!", szUrl);
			
			return false;
		}
		
		if(m_bEmitAlerts)
		{
			GenericClassfulLogMessage lmMessage = GenericClassfulLogMessage("Malware Download issued.", cid);
			
			lmMessage.setString("classification.text", "Malware download issued");			
			lmMessage.setString("download.url", szUrl);
			lmMessage.setString("assessment.impact.severity", "medium");
			
			g_pLogManager->log(LT_DOWNLOAD | LT_LEVEL_LOW, &lmMessage);
		}
		
		return itDownloader->second->downloadFile(szUrl, cid);
	}
	
	
	bool DownloadManager::registerDownloader(Downloader * m_pDownloader, const char * szProtocol)
	{
		if(m_mpDownloaders.find(szProtocol) != m_mpDownloaders.end())
		{
			LOG(LT_LEVEL_CRITICAL | LT_STATUS | LT_DOWNLOAD, "Double DownloadManager registration for protocol \"%s://\"!", szProtocol);
			
			return false;
		}
	
		m_mpDownloaders[szProtocol] = m_pDownloader;		
		return true;
	}
	
	bool DownloadManager::unregisterDownloader(const char * szProtocol)
	{
		return m_mpDownloaders.erase(szProtocol);
	}
	
	void DownloadManager::cleanBlockings()
	{
		unsigned long ulTime = time(0);
		// remove blockings that already timed out anyway
		
		// if we put this on a /16, there may be a lot of blockings and
		// therefore this could be too cpu intensive if done every
		// mainloop iteration
		if(ulTime - m_ulLastCleanup < 3)
			return;
			
		std::map<const char *, unsigned long, DownloaderMapComparator>::iterator j;
			
		for(std::map<const char *, unsigned long, DownloaderMapComparator>::iterator i = m_mulBlockings.begin(); i != m_mulBlockings.end(); i = j)
		{
			j = i;
			++ j;
			
			if(i->second < ulTime)
				m_mulBlockings.erase(i);		
		}
		
		m_ulLastCleanup = time(0); // perhaps the above took several seconds :P
	}
	
	
	
	
	ShellcodeDispatcher::ShellcodeDispatcher(const char * szDirectory, bool bStoreAll)
	{
		m_bStoreAll = bStoreAll;
		
		if(szDirectory)
			m_szShellcodeDirectory = strdup(szDirectory);
		else
		{
			m_szShellcodeDirectory = 0;
			m_bStoreAll = false;
		}
	}
	
	ShellcodeDispatcher::~ShellcodeDispatcher()
	{
		if(m_szShellcodeDirectory)
			free(m_szShellcodeDirectory);
	}
	
		
	bool ShellcodeDispatcher::parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulRemoteHost, CorrelationId cid)
	{
		bool bFound = false;
		
		assert(nLength < 0x40000);
		
		for(std::list<ShellcodeParser *>::iterator i = m_lpParsers.begin(); i != m_lpParsers.end(); ++i)
		{
			if((* i)->parseShellcode(pucShellcode, nLength, ulRemoteHost, cid))
			{
				bFound = true;
				
				if(!m_bStoreAll)
					return true;
			}
		}
		
		if(m_szShellcodeDirectory)
		{
			FILE * pFile;
			char * szFilename;
			
			asprintf(&szFilename, "%s/shellcode-%u.%08x", m_szShellcodeDirectory, time(0), rand());
			pFile = fopen(szFilename, "wb");
			
			if(!pFile)
				LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not open %s for writing!", szFilename);
			else
			{
				fwrite(pucShellcode, 1, nLength, pFile);
				fclose(pFile);
				
				if(!bFound)
					LOG(LT_INTHEWILD | LT_SHELLCODE | LT_LEVEL_CRITICAL | LT_INTHEWILD, "Got an unknown shellcode of %u bytes, wrote to %s.", nLength, szFilename);
			}
			
			free(szFilename);
		}
		else		
			LOG(LT_INTHEWILD | LT_SHELLCODE | LT_LEVEL_CRITICAL | LT_INTHEWILD, "Got an unknown shellcode of %u bytes, discarded.", nLength);
		
		return bFound;
	}
	
		
	void ShellcodeDispatcher::registerParser(ShellcodeParser * pParser)
	{
		m_lpParsers.push_back(pParser);
	}
	
	void ShellcodeDispatcher::unregisterParser(ShellcodeParser * pParser)
	{
		m_lpParsers.remove(pParser);
	}
	
	
	
	void SubmissionDispatcher::registerSubmitter(Submitter * pSubmitter)
	{
		m_lpSubmitters.push_back(pSubmitter);
	}
	
	void SubmissionDispatcher::unregisterSubmitter(Submitter * pSubmitter)
	{
		m_lpSubmitters.remove(pSubmitter);
	}
	
	bool SubmissionDispatcher::submitData(const unsigned char * pData, unsigned int nLength, CorrelationId cid)
	{
		bool bFoundGoodOne = false;
		
		if(!nLength)
		{
			LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Discarded zero-length submission!");
			
			return false;
		}
		
		for(std::list<Submitter *>::iterator i = m_lpSubmitters.begin(); i != m_lpSubmitters.end(); ++i)			
			if((* i)->submitData(pData, nLength, cid))
				bFoundGoodOne = true;
				
		if(bFoundGoodOne)
			LOG(LT_STATUS | LT_LEVEL_MEDIUM | LT_INTHEWILD, "Malware submission of %0.2f kbytes successful.", nLength / 1024.0f);
		else
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Malware submission of %0.2f kbytes got lost.", nLength / 1024.0f);
				
		return bFoundGoodOne;
	}
}
