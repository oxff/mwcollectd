/*
 * Download module for Trivial File Transfer Protocol (TFTP)
 * I hate all those stupid fucking bot authors using TFTP.
 *
 * $Id: download-tftp-module.cpp 252 2005-12-10 19:03:19Z oxff $
 *
 */
 
#include "download-tftp.h"
#include <assert.h>

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new DownloadTftpModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (DownloadTftpModule *) pInstance;
	}
}


bool DownloadTftpModule::start()
{
	if(!m_pCollector->getDownloadManager()->registerDownloader(this, "tftp"))
		return false;
		
	return true;
}

void DownloadTftpModule::stop()
{
	m_pCollector->getDownloadManager()->unregisterDownloader("tftp");
}


NetworkSubscription * DownloadTftpModule::createNetworkSubscription(Socket * pSocket)
{
	return new TftpSubscription(pSocket, m_pCollector->getSubmissionDispatcher());
}

void DownloadTftpModule::freeNetworkSubscription(NetworkSubscription * pSubscription)
{
	delete (TftpSubscription *) pSubscription;
}


bool DownloadTftpModule::downloadFile(const char * szUrl, CorrelationId cid)
{
	char * szCopy;
	char * szFile;
	
	if(strncmp(szUrl, "tftp://", 7) || !strrchr(szUrl + 7, '/'))
		return false;
		
	szUrl += 7;
	szCopy = strdup(szUrl);
	szFile = strrchr(szCopy, '/');
	* szFile = 0;
	++szFile;
	
	sendRequest(szCopy, szFile, cid);	
	
	free(szCopy);

	return true;
}

#define MODE_STRING "octet"

void DownloadTftpModule::sendRequest(const char * szHost, const char * szFile, CorrelationId cid)
{
	char * szRequest;
	int iRequestLength;
	
	{
		iRequestLength = 2 + strlen(szFile) + 1 + sizeof(MODE_STRING);
		szRequest = (char *) malloc(iRequestLength);
		
		* (unsigned short *) szRequest = 0x0100;
		strcpy(szRequest + 2, szFile);
		strcpy(szRequest + 3 + strlen(szFile), MODE_STRING);
	}
	
	{
		void  * pCID = malloc(sizeof(cid));
		unsigned long ulHost = m_pCollector->getNetworkCore()->resolveHostname(szHost);
		Socket * pSocket;
		
		memcpy(pCID, &cid, sizeof(cid));
		
		if(ulHost)
		{
			pSocket = m_pCollector->getNetworkCore()->associateSocket(this, ulHost, 69, m_pConfiguration->getLong(":timeout", 60), true, pCID);
			pSocket->sendDatagram((unsigned char *) szRequest, iRequestLength, ulHost, 69);
		}
	}
	
	free(szRequest);
}
