/*
 * Download module for Trivial File Transfer Protocol (TFTP)
 * I hate all those stupid fucking bot authors using TFTP.
 *
 * $Id: download-tftp-subscription.cpp 211 2005-11-06 17:17:48Z oxff $
 *
 */
 
#include "download-tftp.h"
#include <netinet/in.h>

void TftpSubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	if(nLength < 4 || nLength > 516)
	{
		m_bFinished = true;
		
		return;
	}
		
	switch(* (unsigned short *) pucData)
	{
		case 0x0500:
			if(* (pucData + nLength - 1))
				LOG(LT_LEVEL_MEDIUM | LT_STATUS | LT_DOWNLOAD, "TFTP Server reported error %u!", ntohs(* (unsigned short *) (pucData + 2)));
			else
				LOG(LT_LEVEL_MEDIUM | LT_STATUS | LT_DOWNLOAD, "TFTP Server reported error %u: %s!", ntohs(* (unsigned short *) (pucData + 2)), pucData + 4);
			
			m_bFinished = true;
			
			break;
			
		case 0x0300:
			if(ntohs(* (unsigned short *) (pucData + 2)) != m_iBlock)
			{
				LOG(LT_LEVEL_MEDIUM | LT_STATUS | LT_DOWNLOAD, "Received out-of-order TFTP packet, block was %hu -- expected %i!", ntohs(* (unsigned short *) (pucData + 2)), m_iBlock);
				
				m_bFinished = true;
			}
			else			
				sendAcknowledgement();

			++m_iBlock;
			
			m_sDataBuffer.append((char *) pucData + 4, nLength - 4);
			
			if(nLength < 516)
			{
				if(!m_bFinished)
					m_pSubmissionDispatcher->submitData((unsigned char *) m_sDataBuffer.data(), m_sDataBuffer.size(), m_cid);
					
				DEBUG("CID #2: %08x%08x", (unsigned int) (m_cid >> 32), (unsigned int) (m_cid & 0xFFFFFFFF));
							
				m_bFinished = true;
			}
			
			break;
	}
}

void TftpSubscription::sendAcknowledgement()
{
	unsigned char szBuffer[4] = { 0x00, 0x04, 0, 0 };
	
	* (unsigned short *) (szBuffer + 2) = htons((unsigned short) m_iBlock);
	m_pSocket->sendDatagram(szBuffer, sizeof(szBuffer), m_ulRemoteHost, m_usRemotePort);
}

void TftpSubscription::connectionEtablished()
{
	m_bFinished = false;
	m_iBlock = 1;
}

void TftpSubscription::connectionClosed()
{
	DEBUG("TFTP pairing destroyed.");
}

ConsumptionLevel TftpSubscription::consumptionLevel()
{
	return (m_bFinished ? CL_DROP : CL_OVERTAKE);
}

void TftpSubscription::setUserData(void * p)
{
	memcpy(&m_cid, p, sizeof(m_cid));
	
	DEBUG("CID #1: %08x%08x", (unsigned int) (m_cid >> 32), (unsigned int) (m_cid & 0xFFFFFFFF));
	
	free(p);
}
