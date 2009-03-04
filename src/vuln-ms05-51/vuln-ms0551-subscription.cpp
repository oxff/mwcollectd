/*
 * Simulates MS05-51 (Remote Code Execution in MSDTC).
 *
 * $Id: vuln-ms0551-subscription.cpp 260 2005-12-16 01:21:09Z oxff $
 *
 * If Jovanka's not the one... ;>
 *
 */
 
#include "vuln-ms0551.h"

#include <string.h>

// from http://www.frsirt.com/exploits/20051201.MS05-051msdtc.cpp.php

char peer0_0[72] = {
(char)0x05, (char)0x00, (char)0x0b, (char)0x03, (char)0x10, (char)0x00, (char)0x00, (char)0x00, 
(char)0x48, (char)0x00, (char)0x00, (char)0x00, (char)0x01, (char)0x00, (char)0x00, (char)0x00, 
(char)0xd0, (char)0x16, (char)0xd0, (char)0x16, (char)0x00, (char)0x00, (char)0x00, (char)0x00, 
(char)0x01, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x00, (char)0x01, (char)0x00, 
(char)0xe0, (char)0x0c, (char)0x6b, (char)0x90, (char)0x0b, (char)0xc7, (char)0x67, (char)0x10, 
(char)0xb3, (char)0x17, (char)0x00, (char)0xdd, (char)0x01, (char)0x06, (char)0x62, (char)0xda, 
(char)0x01, (char)0x00, (char)0x00, (char)0x00, (char)0x04, (char)0x5d, (char)0x88, (char)0x8a, 
(char)0xeb, (char)0x1c, (char)0xc9, (char)0x11, (char)0x9f, (char)0xe8, (char)0x08, (char)0x00, 
(char)0x2b, (char)0x10, (char)0x48, (char)0x60, (char)0x02, (char)0x00, (char)0x00, (char)0x00 };

void VulnerabilitySubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	m_sBuffer.append((char *) pucData, nLength);
	
	while(!m_sBuffer.empty())
	{
		switch(m_iStage)
		{
		case 0:
			if(m_sBuffer.size() < sizeof(peer0_0))
				return;
				
			if(memcmp(m_sBuffer.data(), peer0_0, sizeof(peer0_0)))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			++m_iStage;
			
			{
				unsigned char szResponse[128];
				
				for(int i = 0; i < sizeof(szResponse); ++i)
					szResponse[i] = rand();
					
				m_pSocket->sendData(szResponse, sizeof(szResponse));
			}
			
			m_clLevel = CL_OVERTAKE;				
			m_sBuffer.erase();
			
			break;
			
		case 1:
			if(m_sBuffer.size() < 1024)
				return;
				
			if(m_sBuffer[132] == (char) 0xeb)
			{
				CorrelationId cid = g_pLogManager->generateCorrelationIdentifier();
				
				{
					GenericClassfulLogMessage lmMessage = GenericClassfulLogMessage("Got successfully exploited via MS05-51 vulnerability!", cid);
					
					lmMessage.setString("classification.text", "Successful MS05-51 Exploitation");
					
					lmMessage.setString("classification.reference(0).name", "OSVDB-18828");
					lmMessage.setString("classification.reference(0).origin", "osvdb");
					lmMessage.setString("classification.reference(0).url", "http://www.osvdb.org/18828");
					
					lmMessage.setString("assessment.impact.severity", "high");
					lmMessage.setString("assessment.impact.completion", "succeeded");
					lmMessage.setString("assessment.impact.type", "admin");

					lmMessage.setAddress("source(0).node.address(0).address", m_ulRemoteHost);
					lmMessage.setInteger("source(0).service.port", m_usRemotePort);
					
					{
						unsigned long ulAddress;
						unsigned short usPort;
						
						m_pCollector->getNetworkCore()->getLocalAddress(this, &ulAddress, &usPort);					
						lmMessage.setAddress("target(0).node.address(0).address", ulAddress);
						lmMessage.setInteger("target(0).service.port", usPort);
					}
					
					g_pLogManager->log(LT_EXPLOIT | LT_LEVEL_MEDIUM, &lmMessage);
				}
				
				m_pCollector->getShellcodeDispatcher()->parseShellcode((unsigned char *) m_sBuffer.data() + 132, m_sBuffer.size() - 132, m_ulRemoteHost, cid);
			}
			
			{
				unsigned char szResponse[128];
				
				for(int i = 0; i < sizeof(szResponse); ++i)
					szResponse[i] = rand();
					
				szResponse[8] = 0x5c;
				m_pSocket->sendData(szResponse, sizeof(szResponse));	
			}			
			
			++m_iStage;
			
		default:
			// ignore following stuff
			m_sBuffer.erase();
		}
	}
}

void VulnerabilitySubscription::connectionEtablished()
{
	m_clLevel = CL_UNSURE;
	m_iStage = 0;
}

void VulnerabilitySubscription::connectionClosed()
{
}

ConsumptionLevel VulnerabilitySubscription::consumptionLevel()
{	
	return m_clLevel;
}
