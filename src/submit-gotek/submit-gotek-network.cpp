/*
 * G.O.T.E.K. Submission Module
 * Submission module that submits files to a gotekd daemon (-> Alliance!).
 *
 * $Id: submit-gotek-network.cpp 275 2006-01-07 17:16:01Z oxff $
 *
 * `Been waiting so long, for you to arrive.. will give everything for the flash of a smile!'
 *	-- Rocco - Counting the Days
 *
 */
 
#include "submit-gotek.h"
#include <stdlib.h>
#include <arpa/inet.h> // htonl

#include "sha2.h"

void GotekSubscription::connectionEtablished()
{
	m_gsState = GS_VIRGIN;
	
	if(!m_pCollector->getNetworkCore()->setSubscriptionTimeout(this, 900))
		DEBUG("Failed to adjust subscription timeout for Gotek subscription!");
}

void GotekSubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	m_sBuffer.append((char *) pucData, nLength);
	
	while(m_sBuffer.size())
	{
		switch(m_gsState)
		{
		case GS_VIRGIN:
			if(m_sBuffer.size() <  4)
				return;
				
			DEBUG("Connected to G.O.T.E.K. server v%i.%i with protocol v%i.%i...", (int) m_sBuffer[0], (int) m_sBuffer[1], (int) m_sBuffer[2], (int) m_sBuffer[3]);
			m_gsState = GS_PREAUTH;
			
			m_sBuffer.erase(0, 4);
			break;
			
		case GS_PREAUTH:
			{
				unsigned long long ullCookie;
				
				if(m_sBuffer.size() < sizeof(ullCookie))
					return;
					
				ullCookie = * (unsigned long long *) m_sBuffer.data();
				m_sBuffer.erase(0, sizeof(ullCookie));
				
				DEBUG("Got Authentication cookie: %016llx", ullCookie);
				
				{
					unsigned char pucHash[64];
					unsigned char pucBlock[sizeof(ullCookie) + m_aiAuthInfo.nKeySize];
					
					memcpy(pucBlock, m_aiAuthInfo.pucKey, m_aiAuthInfo.nKeySize);
					memcpy(pucBlock + m_aiAuthInfo.nKeySize, &ullCookie, sizeof(ullCookie));
					sha512(pucBlock, m_aiAuthInfo.nKeySize + sizeof(ullCookie), pucHash);
					
					m_pSocket->sendData(m_aiAuthInfo.pucUser, sizeof(m_aiAuthInfo.pucUser));
					m_pSocket->sendData(pucHash, sizeof(pucHash));
				}
				
				m_gsState = GS_INAUTH;
			}
			
			break;
			
		case GS_INAUTH:
			if(m_sBuffer[0] != (char) 0xaa)
			{
				LOG(LT_STATUS | LT_LEVEL_CRITICAL, "G.O.T.E.K. Server did not acknowledge authorization!");
				
				m_bFaulty = true;
				return;
			}
			
			LOG(LT_STATUS | LT_LEVEL_LOW, "Successfully authorized at G.O.T.E.K. Server.");
			m_sBuffer.erase(0, 1);
			
			gotekSessionEtablished();
			m_gsState = GS_IDLE;
			
			if(m_sBuffer.size())
				incomingGotekData();
			
			break;
			
		default:
			if(!incomingGotekData())
				m_bFaulty = true;
		}
	}
}

// =============================================================================

void GotekControlSubscription::gotekSessionEtablished()
{	
	m_pSocket->sendData((unsigned char *) "\x55", 1);
}

void GotekControlSubscription::connectionClosed()
{
	LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Lost control connection to G.O.T.E.K. server!");
	
	m_pTop->connectionClosed();
}

bool GotekControlSubscription::incomingGotekData()
{
	switch(m_gsState)
	{
	case GS_IDLE:
		if(m_sBuffer[0] == (char) 0xff)
		{
			m_pSocket->sendData((unsigned char *) "\xff", 1);
			DEBUG("G.O.T.E.K. Ping? Pong!");
		
			return true;
		}
		else
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "G.O.T.E.K. server sent unexpected non-ping sequence (0x%02x) in idle state!", (unsigned int) m_sBuffer[0]);
			m_sBuffer.erase();
			
			return false;
		}
		
	case GSC_AWAITING_RESPONSE:
		if(m_sBuffer[0] == '\x55')
		{
			DEBUG("Binary for Prelude CID %016llx already existing in database.", m_lgsPendingSamples.front().ullLogID);
			
			free(m_lgsPendingSamples.front().pucSample);
			m_lgsPendingSamples.pop_front();
		}		
		else if(m_sBuffer[0] == '\xaa')
		{
			GotekSample gsUpload= m_lgsPendingSamples.front();
			
			DEBUG("Binary for Prelude CID %016llx requested to be uploaded!", gsUpload.ullLogID);
			assert(!m_lgsPendingSamples.empty());
			
			m_pTop->m_gucUpload.uploadSample(&gsUpload);
			m_lgsPendingSamples.pop_front();
		}
		else
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "G.O.T.E.K. server sent unexpected response to upload request!");
			
			return false;
		}
		
		m_sBuffer.erase(0, 1);
		
		if(m_lgsPendingSamples.empty())
			m_gsState = GS_IDLE;
		
	default:
		return true;
			
	}
}

bool GotekControlSubscription::addRequest(GotekSample * pSample)
{
	GotekSample gsSample = * pSample;
	unsigned char szBuffer[1 + 64 + sizeof(unsigned long long)];
	
	szBuffer[0] = 0x01;
	memcpy(szBuffer + 1, pSample->pucHash, 64);
	* ((unsigned long long *) &szBuffer[65]) = gsSample.ullLogID;
	
	m_pSocket->sendData(szBuffer, sizeof(szBuffer));
	m_gsState = GSC_AWAITING_RESPONSE;
	
	m_lgsPendingSamples.push_back(gsSample);
}

// =============================================================================
// Threestone! :-* :D O_o
// =============================================================================

void GotekDataSubscription::gotekSessionEtablished()
{
	{
		unsigned char pucHeaderBuffer[1 + sizeof(unsigned long long) + sizeof(unsigned int)];
		
		pucHeaderBuffer[0] = 0xaa;
		* ((unsigned long long *) &pucHeaderBuffer[1]) = m_gsSample.ullLogID;
		* ((unsigned int *) &pucHeaderBuffer[1 + sizeof(unsigned long long)]) = htonl(m_gsSample.nSampleSize);
		
		m_pSocket->sendData(pucHeaderBuffer, sizeof(pucHeaderBuffer));
	}
	
	m_pSocket->sendData(m_gsSample.pucSample, m_gsSample.nSampleSize);
}

void GotekDataSubscription::connectionLost()
{
	LOG(LT_STATUS | LT_LEVEL_MEDIUM, "Upload of binary for Prelude CID %016llx failed (%.2f kB); retrying!", m_gsSample.ullLogID, m_gsSample.nSampleSize / 1024.0f);
	
	m_pCoordinator->uploadSample(&m_gsSample);
}
