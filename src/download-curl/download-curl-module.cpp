/*
 * libCURL Download Module
 * Download HTTP & FTP URLs with libCURL in a consumer / producer thread dual side environment.
 *
 * $Id: download-curl-module.cpp 203 2005-11-05 00:05:49Z oxff $
 *
 */
 
#include "download-curl.h"

#include <string.h>

extern "C"
{
	void * CreateInstance()
	{
		return new DownloadModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (DownloadModule *) pInstance;
	}
}


bool DownloadModule::start()
{
	if(!m_pCollector->getDownloadManager()->registerDownloader(this, "http") || !m_pCollector->getDownloadManager()->registerDownloader(this, "https") || !m_pCollector->getDownloadManager()->registerDownloader(this, "ftp"))
		return false;
	try
	{
		m_pContainer = new DownloadContainer(m_pCollector->getSubmissionDispatcher(), m_pConfiguration->getLong(":limits:filesize", 1024 * 64), m_pConfiguration->getLong(":limits:http-redirects", 3), m_pConfiguration->getString(":user-agent", "mwcollect " MWCD_VERSION), m_pConfiguration->getLong(":limits:timeout", 300));
		
		m_pContainer->startThread();
	}
	catch(const char * szError)
	{
		LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not create libCURL download container: %s", szError);
		
		return false;
	}
	
	return true;
}

void DownloadModule::stop()
{
	delete m_pContainer;
}

void DownloadModule::loop()
{
	m_pContainer->checkSubmissions();
}

bool DownloadModule::downloadFile(const char * szURL, CorrelationId cid)
{	
	return m_pContainer->addDownload(szURL, cid);
}
