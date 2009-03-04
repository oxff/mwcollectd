/*
 * libCURL Download Module
 * Download HTTP & FTP URLs with libCURL in a consumer / producer thread dual side environment.
 *
 * $Id: download-curl-container.cpp 276 2006-01-07 18:33:36Z oxff $
 *
 */
 
#include "download-curl.h"
#include <string.h>
#if defined(OBSD_FLAVOURED) /* select() */
	#include <sys/types.h>
	#include <sys/time.h>
	#include <string.h>
	#include <unistd.h>
#else
	#include <sys/select.h>
#endif

void * __attribute__((cdecl)) threadWrapper(void * pParam)
{
	((DownloadContainer *) pParam)->containerThread();
	
	return 0;
}

DownloadContainer::DownloadContainer(SubmissionDispatcher * pSubmissionDispatcher, unsigned int nMaxFilesize, unsigned int nMaxRedirects, const char * szUserAgent, unsigned long ulTimeout)
{
	// copy configuration
	m_nMaxFilesize = nMaxFilesize;
	m_nMaxRedirects = nMaxRedirects;
	m_szUserAgent = szUserAgent;
	m_ulTimeout = ulTimeout;
	
	m_pDispatcher = pSubmissionDispatcher;

	// keep track of number of running downloads
	m_nRunningDownloads = 0;
	m_bRun = true;

	// whole bunch of mutexes that coordinate Mutex wisely	
	pthread_mutex_init(&m_ptmDownloadMutex, 0);
	pthread_mutex_init(&m_ptmSubmissionMutex, 0);
	pthread_mutex_init(&m_ptmLogMutex, 0);
	pthread_cond_init(&m_ptcDownloadAvailable, 0);

	// unless logging is required, it's prohibited since some log modules might not be thread safe
	pthread_mutex_lock(&m_ptmLogMutex);
}

void DownloadContainer::startThread()
{		
	// create the thread which immediately falls asleep since m_nRunningDownloads == 0	
	if(pthread_create(&m_ptThread, 0, &threadWrapper, this))
		throw "Creating libCURL thread failed!";
}

DownloadContainer::~DownloadContainer()
{
	// kick everything that's still waiting to be processed out
	checkSubmissions();
	
	// exit thread
	m_bRun = false;
	pthread_cond_signal(&m_ptcDownloadAvailable); // ensure sleeping thread exits
	
	// clean up the mess
	pthread_cond_destroy(&m_ptcDownloadAvailable);
	pthread_mutex_destroy(&m_ptmLogMutex);
	pthread_mutex_destroy(&m_ptmSubmissionMutex);
	pthread_mutex_destroy(&m_ptmDownloadMutex);
}

bool DownloadContainer::addDownload(const char * szURL, CorrelationId cid)
{
	DataStruct dsNew;
	
	dsNew.szURL = strdup(szURL);
	dsNew.cid = cid;
	
	// ensure thread safety and add download to list
	pthread_mutex_lock(&m_ptmDownloadMutex);
	m_lszPendingDownloads.push_back(dsNew);
	
	// allow container thread to continue and wake up if fell asleep
	pthread_mutex_unlock(&m_ptmDownloadMutex);
	pthread_cond_signal(&m_ptcDownloadAvailable);
}

void DownloadContainer::checkSubmissions()
{
	// allow for some logging if neccessary
	pthread_mutex_unlock(&m_ptmLogMutex);
	pthread_mutex_lock(&m_ptmLogMutex);
	
	// acquire lock
	pthread_mutex_lock(&m_ptmSubmissionMutex);
	
	// process all pending submissions
	for(std::list<SubmissionInfo>::iterator i = m_lsiPendingSubmissions.begin(); i != m_lsiPendingSubmissions.end(); ++i)
	{
		m_pDispatcher->submitData(i->pData, i->nLength, i->cid);
		
		free(i->pData);
	}
	
	m_lsiPendingSubmissions.clear();
	
	// allow container thread to continue
	pthread_mutex_unlock(&m_ptmSubmissionMutex);
	
	// allow for some logging if neccessary
	pthread_mutex_unlock(&m_ptmLogMutex);
	pthread_mutex_lock(&m_ptmLogMutex);
}


unsigned long DownloadContainer::containerThread()
{
	if(!threadStartup())
		return 1;
	
	while(m_bRun)
	{
		{
			// acquire lock for download queue
			pthread_mutex_lock(&m_ptmDownloadMutex);
			
			// if nothing to do, sleep
			while(!m_nRunningDownloads && m_lszPendingDownloads.empty() && m_bRun)
				pthread_cond_wait(&m_ptcDownloadAvailable, &m_ptmDownloadMutex);
				
			if(!m_bRun)
			{
				pthread_mutex_unlock(&m_ptmDownloadMutex);
				
				break;
			}
			
			for(std::list<DataStruct>::iterator i = m_lszPendingDownloads.begin(); i != m_lszPendingDownloads.end(); ++i)
			{
				createDownload(i->szURL, i->cid);
				// free(i->szURL); // removed strdup in createDownload
			}
			
			m_lszPendingDownloads.clear();
			
			// let the main thread push more
			pthread_mutex_unlock(&m_ptmDownloadMutex);
		}
		
		{
			int m;
			fd_set a, b, c;
			struct timeval tvTimeout;
			
			FD_ZERO(&a); FD_ZERO(&b); FD_ZERO(&c);			
			tvTimeout.tv_sec = 1;
			tvTimeout.tv_usec = 500;
			
			// wait for incoming data and let curl process it, wait max 1 second because of internal curl timeouts
			curl_multi_fdset(m_pCurlMulti, &a, &b, &c, &m);
			select(m, &a, &b, &c, &tvTimeout);
			curl_multi_perform(m_pCurlMulti, &m);
			
			{
				CURLMsg * pMessage;
				DataStruct * pInfo;
				const char * szEffectiveURL;
				CURL * pHandle;
				
				while((pMessage = curl_multi_info_read(m_pCurlMulti, &m)))
				{
					if(pMessage->msg != CURLMSG_DONE)
						continue;
					
					-- m_nRunningDownloads;
					
					curl_easy_getinfo(pMessage->easy_handle, CURLINFO_PRIVATE, &pInfo);
					
					if(pMessage->data.result)
					{
						pthread_mutex_lock(&m_ptmLogMutex);
						LOG(LT_DOWNLOAD | LT_LEVEL_LOW, "Download of %s failed with code %i: %s!", pInfo->szURL, pMessage->data.result, curl_easy_strerror(pMessage->data.result));
						pthread_mutex_unlock(&m_ptmLogMutex);
					}
					else
					{
						SubmissionInfo siSubmission;
						
						curl_easy_getinfo(pMessage->easy_handle, CURLINFO_EFFECTIVE_URL, &szEffectiveURL);
						
						pthread_mutex_lock(&m_ptmLogMutex);
						LOG(LT_DOWNLOAD | LT_INTHEWILD | LT_LEVEL_LOW, "Successfully downloaded %s from effective URL %s (%u bytes).", pInfo->szURL, szEffectiveURL, pInfo->nSize);
						pthread_mutex_unlock(&m_ptmLogMutex);
						
						siSubmission.nLength = pInfo->nSize;
						siSubmission.pData = pInfo->pucData;
						siSubmission.cid = pInfo->cid;
						
						pthread_mutex_lock(&m_ptmSubmissionMutex);
						m_lsiPendingSubmissions.push_back(siSubmission);
						pthread_mutex_unlock(&m_ptmSubmissionMutex);
					}
					
					pHandle = pMessage->easy_handle;
					curl_multi_remove_handle(m_pCurlMulti, pHandle);
					curl_easy_cleanup(pHandle);
					
					free(pInfo->szURL);
					free(pInfo);
				}
			}
		}
	}
	
	threadCleanup();
	return 0;
}

bool DownloadContainer::threadStartup()
{
	CURLcode iError;
	
	if((iError = curl_global_init(CURL_GLOBAL_SSL)) != 0)
	{
		pthread_mutex_lock(&m_ptmLogMutex);
		LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Could not initialize libCURL: %s", curl_easy_strerror(iError));
		pthread_mutex_unlock(&m_ptmLogMutex);
		
		return false;
	}
	
	m_pCurlMulti = curl_multi_init();
	
	return true;
}

void DownloadContainer::threadCleanup()
{
	curl_global_cleanup();
}

size_t writeFunction(void * pNewData, size_t a, size_t b, void * pUser)
{
	((DataStruct *) pUser)->pucData = (unsigned char *) realloc(((DataStruct *) pUser)->pucData, ((DataStruct *) pUser)->nSize + a * b);
	memcpy(((DataStruct *) pUser)->pucData + ((DataStruct *) pUser)->nSize, pNewData, a * b);
	((DataStruct *) pUser)->nSize += a * b;
	
	return (a * b);
}

void DownloadContainer::createDownload(char * szURL, CorrelationId cid)
{
	CURL * pDownload;
	
	pDownload = curl_easy_init();
	
	{ // for all downloads
		DataStruct * pInfo = (DataStruct *) malloc(sizeof(DataStruct));
		
		pInfo->pucData = 0;
		pInfo->nSize = 0;
		pInfo->szURL = szURL;
		pInfo->cid = cid;
		
		curl_easy_setopt(pDownload, CURLOPT_NOPROGRESS, 1);
		curl_easy_setopt(pDownload, CURLOPT_NOSIGNAL, 1);
		
		curl_easy_setopt(pDownload, CURLOPT_URL, pInfo->szURL);
		curl_easy_setopt(pDownload, CURLOPT_MAXFILESIZE, m_nMaxFilesize);
		
		curl_easy_setopt(pDownload, CURLOPT_PRIVATE, pInfo);
		curl_easy_setopt(pDownload, CURLOPT_WRITEDATA, pInfo);
		curl_easy_setopt(pDownload, CURLOPT_WRITEFUNCTION, &writeFunction);
		
		curl_easy_setopt(pDownload, CURLOPT_TIMEOUT, m_ulTimeout);
	}
	
	if(!strncmp(szURL, "http://", 7))
	{
		curl_easy_setopt(pDownload, CURLOPT_FOLLOWLOCATION, 1);
		curl_easy_setopt(pDownload, CURLOPT_MAXREDIRS, m_nMaxRedirects);
		curl_easy_setopt(pDownload, CURLOPT_USERAGENT, m_szUserAgent);
		
		if(!strncmp(szURL, "https://", 8))
		{
			curl_easy_setopt(pDownload, CURLOPT_SSL_VERIFYHOST, false);
                	curl_easy_setopt(pDownload, CURLOPT_SSL_VERIFYPEER, false);
                }
	}
	
	curl_multi_add_handle(m_pCurlMulti, pDownload);
	++m_nRunningDownloads;
}
