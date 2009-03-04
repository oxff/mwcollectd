/*
 * libCURL Download Module
 * Download HTTP & FTP URLs with libCURL in a consumer / producer thread dual side environment.
 *
 * $Id: download-curl.h 203 2005-11-05 00:05:49Z oxff $
 *
 */
 
#ifndef __MWCMOD_DOWNLOADCURL
#define __MWCMOD_DOWNLOADCURL

#include <mwcollect/core.h>
using namespace mwccore;

#include <list>
#include <pthread.h>
#include <curl/curl.h>


class DownloadContainer;

class DownloadModule : public Module, public Downloader
{
public:	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	virtual void loop();
	
	virtual bool downloadFile(const char * szURL, CorrelationId cid);
	
private:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
	DownloadContainer * m_pContainer;
};


struct DataStruct
{
	unsigned char * pucData;
	unsigned int nSize;
	
	char * szURL;
	
	CorrelationId cid;
};

struct SubmissionInfo
{
	unsigned char * pData;
	unsigned int nLength;
	
	CorrelationId cid;
};

class DownloadContainer
{
public:
	DownloadContainer(SubmissionDispatcher * pDispatcher, unsigned int nMaxFilesize, unsigned int nMaxRedirects, const char * szUserAgent, unsigned long ulTimeout);
	~DownloadContainer();
	void startThread();
	
	unsigned long containerThread();
	
	bool addDownload(const char * szUrl, CorrelationId cid);
	void checkSubmissions();
	
protected:
	bool threadStartup();
	void threadCleanup();
	
	void createDownload(char * szURL, CorrelationId cid);

private:
	// shared variables
	std::list<DataStruct> m_lszPendingDownloads;
	std::list<SubmissionInfo> m_lsiPendingSubmissions;
	unsigned int m_nRunningDownloads;
	bool m_bRun;
	
	// configuration
	unsigned int m_nMaxFilesize, m_nMaxRedirects;
	const char * m_szUserAgent;
	unsigned long m_ulTimeout;
	
	// threading coordination
	pthread_t m_ptThread;
	pthread_mutex_t m_ptmDownloadMutex, m_ptmSubmissionMutex, m_ptmLogMutex;
	pthread_cond_t m_ptcDownloadAvailable;
	
	
	// thread's stuff
	SubmissionDispatcher * m_pDispatcher;
	
	CURLM * m_pCurlMulti;
};

#endif // __MWCMOD_DOWNLOADCURL
