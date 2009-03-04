/*
 * G.O.T.E.K. Submission Module
 * Submission module that submits files to a gotekd daemon (-> Alliance!).
 *
 * $Id: submit-gotek.cpp 275 2006-01-07 17:16:01Z oxff $
 *
 * `Fickey, Fickey, Attz!'
 *	-- Katruenn's Wall && Elephant Beer
 *
 */
 
#include "submit-gotek.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "sha2.h"

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new SubmitterModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (SubmitterModule *) pInstance;
	}
}


bool SubmitterModule::start()
{
	m_pChild = 0;
	
	if(!m_pConfiguration->leafExists(":auth:username"))
	{
		LOG(LT_STATUS | LT_LEVEL_CRITICAL, "No username configured for G.O.T.E.K.!");
		
		return false;
	}
	else if(strlen(m_pConfiguration->getString(":auth:username", 0)) > 32)
	{
		LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Username for G.O.T.E.K. too long!");
		
		return false;
	}
	
	// read key file and store in memory
	// so we can reconnect even after dropping privilegues,
	// if the key file is root:root 0400
	
	{
		FILE * pKeyFile;
		int iRead;
		
		if(!(pKeyFile = fopen(m_pConfiguration->getString(":auth:key-file", "conf/gotek.key"), "rb")))
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not open G.O.T.E.K. key file \"%s\" for reading!", m_pConfiguration->getString(":auth:key-file", "conf/gotek.key"));
			
			return false;
		}
		
		m_nKeySize = m_pConfiguration->getLong(":auth:key-size", 1024);
		m_pucKey = (unsigned char *) malloc(m_nKeySize);
		assert(m_pucKey != 0);
		
		if((iRead = fread(m_pucKey, 1, m_nKeySize, pKeyFile)) < m_nKeySize)
		{
			if(iRead >= 0)
				LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could only read %i bytes of %u bytes expected key size!", iRead, m_nKeySize);
			else
				LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Reading from G.O.T.E.K. key file failed: %s!", strerror(errno));
				
			free(m_pucKey);
			return false;
		}
		
		fclose(pKeyFile);
	}
	
	{
		const char * szUser = m_pConfiguration->getString(":auth:username", 0);
		
		m_aiAuthInfo.pucKey = m_pucKey;
		m_aiAuthInfo.nKeySize = m_nKeySize;	
		
		memset(m_aiAuthInfo.pucUser, 0, sizeof(m_aiAuthInfo.pucUser));
		memcpy(m_aiAuthInfo.pucUser, szUser, strlen(szUser));
		
		m_gucUpload.m_pTop = this;
	}
	
	m_bLinkPrelude = m_pConfiguration->getLong(":link-prelude", 1) != 0;

	m_pCollector->getSubmissionDispatcher()->registerSubmitter(this);
	
	return connectServer(this);
}

void SubmitterModule::stop()
{
	m_pCollector->getSubmissionDispatcher()->unregisterSubmitter(this);
	
	// try to hide key artefacts...
	for(unsigned int n = 0; n < m_nKeySize; ++n)
		m_pucKey[n] = rand() % 0x100;
		
	free(m_pucKey);
}

NetworkSubscription * SubmitterModule::createNetworkSubscription(Socket * pSocket)
{
	const char * szUser = m_pConfiguration->getString(":auth:username", 0);
	
	GotekControlSubscription * pSubs = new GotekControlSubscription(m_pCollector, pSocket, this, m_aiAuthInfo);	
	m_pChild = pSubs;
	return pSubs;
}

void SubmitterModule::freeNetworkSubscription(NetworkSubscription * pSubs)
{
	if(pSubs == (NetworkSubscription *) m_pChild)
		m_pChild = 0;
		
	delete (GotekSubscription *) pSubs;
}

bool SubmitterModule::connectServer(NetworkSubscriptionFactory * pFactory)
{
	if(pFactory == this && m_pChild)
		return false;
		
	if(!m_pCollector->getNetworkCore()->connectSocket(pFactory, m_pCollector->getNetworkCore()->resolveHostname(m_pConfiguration->getString(":server:host", "alliance.mwcollect.org")), (unsigned short) m_pConfiguration->getLong(":server:port", 34109)))
	{
		LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Connecting to G.O.T.E.K. server failed.");
		
		return false;
	}
	
	if(pFactory == this)
		m_bConnected = true;
		
	return true;
}

void SubmitterModule::connectionClosed()
{
	m_ulNextConnect = time(0) + 5;
	m_bConnected = false;
}

void SubmitterModule::loop()
{
	if(m_bConnected)
		return;
		
	if(m_ulNextConnect > time(0))
		return;
		
	if(connectServer(this))
		return;
		
	m_ulNextConnect = time(0) + 30;
}


bool SubmitterModule::submitData(const unsigned char * pData, unsigned int nLength, CorrelationId cid)
{
	if(!m_bConnected)
		return false;

	GotekSample gsSample;
	
	sha512((unsigned char *) pData, nLength, gsSample.pucHash);
	
	gsSample.pucSample = (unsigned char *) malloc(nLength);
	memcpy(gsSample.pucSample, pData, nLength);
	gsSample.ullLogID = 0;
	assert(gsSample.pucSample != 0);
	
	gsSample.nSampleSize = nLength;	
	return m_pChild->addRequest(&gsSample);
}


// =============================================================================
// Dreistein? Dreistein! ^^ :-* ;)
// =============================================================================


NetworkSubscription * GotekUploadCoordinator::createNetworkSubscription(Socket * pSocket)
{	
	return new GotekDataSubscription(m_pCollector, pSocket, this, m_pTop->m_aiAuthInfo, &m_gsCurrentSample);
}

void GotekUploadCoordinator::freeNetworkSubscription(NetworkSubscription * pSubs)
{
	delete (GotekDataSubscription *) pSubs;
}

void GotekUploadCoordinator::uploadSample(GotekSample * pucSample)
{
	m_gsCurrentSample = * pucSample;
	
	m_pTop->connectServer(this);
}
